-- Data Format:
--     HMAC Signature (16)
--     Payload (?)
--         IV (16)
--         Digest (?)
--             Pad Length (2)
--             Null Flag (1)
--             Data (?)
-- Usage:
-- SELECT enclave_decrypt(enclave_encrypt(CAST('2014-07-23 08:41:52.004991-07' as timestamp), 'password'), 'password', CAST(null as timestamp));
-- SELECT enclave_verify(enclave_encrypt(CAST('2014-07-23 08:41:52.004991-07' as timestamp), 'password'), 'password');


CREATE EXTENSION pgcrypto;


-- Uninstall potentially outdated functions.
DO $$
DECLARE
	o_id integer;
	statement text;
BEGIN
	FOR o_id IN SELECT oid FROM pg_proc WHERE proname LIKE 'enclave_%' AND pg_function_is_visible(oid) LOOP
		statement = format('DROP FUNCTION %s(%s);', o_id::regproc, pg_get_function_identity_arguments(o_id));
		RAISE DEBUG 'Executing: %', statement;
		EXECUTE statement;
	END LOOP;
END $$;


CREATE OR REPLACE FUNCTION enclave_encrypt (data anyelement, secret bytea) RETURNS bytea AS $$
DECLARE
	iv bytea;
	null_flag text;
	pad_length integer;
	text_data text;
	digest bytea;
	payload bytea;
	sig bytea;
BEGIN
	iv = gen_random_bytes(16);
	
	IF data = null THEN
		null_flag = '1'; -- Sentinel to disambiguate null from 'null' from ''.
	ELSE
		null_flag = '0';
	END IF;
	
	secret = digest(secret, 'sha256');
	text_data = CAST(data as text); -- Convert postgres type to postgres string.
	pad_length = (32 - (length(text_data) + 3)) % 32; -- Calculate pad length.
	text_data = lpad(CAST(pad_length as text), 2, '0') || null_flag || rpad(text_data, length(text_data) + pad_length, '0'); -- Pad string and prefix with pad length.
	digest = encrypt_iv(decode(text_data, 'escape'), secret, iv, 'aes-cbc/pad:none'); -- text -> bytea and encrypt.
	payload = iv || digest;
	sig = hmac(payload, secret, 'sha256');
	
	RAISE DEBUG 'Encrypting...';
	RAISE DEBUG 'Full:        %', sig || payload;
	RAISE DEBUG 'Sig:         %', sig;
	RAISE DEBUG 'Payload:     %', payload;
	RAISE DEBUG 'IV:          %', iv;
	RAISE DEBUG 'Digest:      %', digest;
	RAISE DEBUG 'Padded Data: %', text_data;
	RAISE DEBUG 'Pad Length:  %', pad_length;
	RAISE DEBUG 'Data:        %', CAST(data as text);
	RETURN sig || payload; -- Return sig(iv + payload) + IV + payload.
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION enclave_decrypt (digest bytea, secret bytea, type anyelement) RETURNS anyelement AS $$
DECLARE
	sig bytea;
	payload bytea;
	iv bytea;
	data text;
	result ALIAS FOR $0;
BEGIN
	RAISE DEBUG 'Decrypting...';
	RAISE DEBUG 'Full:        %', digest;
	secret = digest(secret, 'sha256');
	sig = substring(digest, 0, 33); -- Signature is first 32 bytes.
	payload = substring(digest, 33);
	RAISE DEBUG 'Sig:         %', sig;
	RAISE DEBUG 'Payload:     %', payload;
	
	IF sig = hmac(payload, secret, 'sha256') THEN 
		iv = substring(payload, 0, 17); -- IV is first 16 bytes.
		digest = substring(payload, 17);
		
		RAISE DEBUG 'IV:          %', iv;
		RAISE DEBUG 'Digest:      %', digest;
		data = encode(decrypt_iv(digest, secret, iv, 'aes-cbc/pad:none'), 'escape'); -- bytea -> text.
		RAISE DEBUG 'Padded Data: %', data;
		RAISE DEBUG 'Pad Length:  %', CAST(substring(data, 0, 3) as integer);
		data = substring(data, 3, length(data) - CAST(substring(data, 0, 3) as integer) - 2); -- First 2 characters are pad length.
		RAISE DEBUG 'Data:        %', data;
		
		IF substring(data, 0, 2) = '1' THEN
			RETURN null;
		ELSE
			result = substring(data, 2); -- Turn postgres text into actual postgres type.
			RETURN result;
		END IF;
	ELSE
		RAISE EXCEPTION 'Bad signature.' USING HINT = 'You probably don''t have the correct secret. This also should never happen.';
		RETURN null;
	END IF;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION enclave_verify (digest bytea, secret bytea) RETURNS bool AS $$
BEGIN
	RAISE DEBUG 'Sig:         %', substring(digest, 0, 33);
	RAISE DEBUG 'Payload:     %', substring(digest, 33);
	RAISE DEBUG 'Sig:         %', hmac(substring(digest, 33), digest(secret, 'sha256'), 'sha256');
	RETURN substring(digest, 0, 33) = hmac(substring(digest, 33), digest(secret, 'sha256'), 'sha256');
END;
$$ LANGUAGE plpgsql;
