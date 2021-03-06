-- Data Format:
--     HMAC Signature (16 bytes, SHA-256)
--     Payload (?, AES-256 (CBC, PKCS#7 Padding))
--         IV (16 bytes)
--         Digest (?)
--             Data Flag (1 byte, \x00: Null, \x01: Data. Disambiguates null from 'null' from ''.)
--             Data (?)
-- Usage:
-- SELECT enclave_verify(enclave_encrypt('2014-07-23 08:41:52.004991-07'::timestamp, 'password'), 'password');
-- SELECT enclave_decrypt(enclave_encrypt('2014-07-23 08:41:52.004991-07'::timestamp, 'password'), 'password', null::timestamp);
-- SELECT enclave_verify_and_decrypt(enclave_encrypt('2014-07-23 08:41:52.004991-07'::timestamp, 'password'), 'password', null::timestamp);


CREATE EXTENSION IF NOT EXISTS pgcrypto;


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
	byte_data bytea;
	digest bytea;
	payload bytea;
	sig bytea;
BEGIN
	iv = gen_random_bytes(16);
	
	IF data IS NOT DISTINCT FROM null THEN
		byte_data = '\x00'::bytea;
	ELSE
		IF pg_typeof(data)::text = 'bytea' THEN -- bytea can't be decoded as it already is.
			byte_data = '\x01'::bytea || data;
		ELSE
			byte_data = '\x01'::bytea || decode(data::text, 'escape');
		END IF;
	END IF;
	
	secret = digest(secret, 'sha256');
	digest = encrypt_iv(byte_data, secret, iv, 'aes-cbc/pad:pkcs');
	payload = iv || digest;
	sig = hmac(payload, secret, 'sha256');
	RETURN sig || payload;
END;
$$ LANGUAGE plpgsql;
COMMENT ON FUNCTION enclave_encrypt (data anyelement, secret bytea) IS 'Encrypt data with a given secret, using AES-256 with CBC and PKCS#7 Padding, and signed with HMAC-SHA-256.';


CREATE OR REPLACE FUNCTION enclave_verify (digest bytea, secret bytea) RETURNS bool AS $$
BEGIN
	RETURN substring(digest, 0, 33) = hmac(substring(digest, 33), digest(secret, 'sha256'), 'sha256');
END;
$$ LANGUAGE plpgsql;
COMMENT ON FUNCTION enclave_verify (digest bytea, secret bytea) IS 'Verify the HMAC-SHA-256 signature of encrypted data.';


CREATE OR REPLACE FUNCTION enclave_decrypt (digest bytea, secret bytea, type anyelement) RETURNS anyelement AS $$
DECLARE
	payload bytea;
	iv bytea;
	data bytea;
	result ALIAS FOR $0;
BEGIN
	payload = substring(digest, 33);
	
	iv = substring(payload, 0, 17);
	digest = substring(payload, 17);
	
	data = decrypt_iv(digest, digest(secret, 'sha256'), iv, 'aes-cbc/pad:pkcs');
	
	IF get_byte(data, 0) = 0 THEN
		RETURN null;
	ELSE
		IF pg_typeof(type)::text = 'bytea' THEN -- We've already got the correct type.
			result = substring(data, 2);
		ELSE
			result = substring(encode(data, 'escape'), 2); -- Turn postgres text into actual postgres type.
		END IF;
		
		RETURN result;
	END IF;
END;
$$ LANGUAGE plpgsql;
COMMENT ON FUNCTION enclave_decrypt (digest bytea, secret bytea, type anyelement) IS 'enclave_encrypt''s inverse. Requires the additional type, which should be an element of the same expected retunr type.';


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
COMMENT ON FUNCTION enclave_verify_and_decrypt (digest bytea, secret bytea, type anyelement) IS 'Helper function that chains enclave_verify and enclave_decrypt.';
