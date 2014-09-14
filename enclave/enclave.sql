-- Data Format:
--     HMAC Signature (16)
--     Payload (?)
--         IV (16)
--         Digest (?)
--             Pad Length (2)
--             Null Flag (1)
--             Data (?)
-- Usage:
-- SELECT enclave_verify(enclave_encrypt(CAST('2014-07-23 08:41:52.004991-07' as timestamp), 'password'), 'password');
-- SELECT enclave_decrypt(enclave_encrypt(CAST('2014-07-23 08:41:52.004991-07' as timestamp), 'password'), 'password', CAST(null as timestamp));
-- SELECT enclave_verify_and_decrypt(enclave_encrypt(CAST('2014-07-23 08:41:52.004991-07' as timestamp), 'password'), 'password', CAST(null as timestamp));


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
	RETURN sig || payload; -- Return sig(iv + payload) + IV + payload.
END;
$$ LANGUAGE plpgsql;

	
CREATE OR REPLACE FUNCTION enclave_verify (digest bytea, secret bytea) RETURNS bool AS $$
BEGIN
	RETURN substring(digest, 0, 33) = hmac(substring(digest, 33), digest(secret, 'sha256'), 'sha256');
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION enclave_decrypt (digest bytea, secret bytea, type anyelement) RETURNS anyelement AS $$
DECLARE
	payload bytea;
	iv bytea;
	data text;
	result ALIAS FOR $0;
BEGIN
	payload = substring(digest, 33);
	
	iv = substring(payload, 0, 17); -- IV is first 16 bytes.
	digest = substring(payload, 17);
	
	data = encode(decrypt_iv(digest, digest(secret, 'sha256'), iv, 'aes-cbc/pad:none'), 'escape'); -- bytea -> text.
	data = substring(data, 3, length(data) - CAST(substring(data, 0, 3) as integer) - 2); -- First 2 characters are pad length.
	
	IF substring(data, 0, 2) = '1' THEN
		RETURN null;
	ELSE
		result = substring(data, 2); -- Turn postgres text into actual postgres type.
		RETURN result;
	END IF;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION enclave_verify_and_decrypt (digest bytea, secret bytea, type anyelement) RETURNS anyelement AS $$
DECLARE
	result ALIAS FOR $0;
BEGIN
	IF enclave_verify(digest, secret) THEN
		result = enclave_decrypt(digest, secret, type);
		RETURN result;
	ELSE
		RAISE EXCEPTION 'Bad signature.' USING HINT = 'You probably don''t have the correct secret.';
		RETURN null;
	END IF;
END;
$$ LANGUAGE plpgsql;
