# -----------------------------------------BEGIN StrongJWT Class Definition------------------------------------------
import json
import html
import urllib
import requests
import jwt as jsonwebtoken
from jwt import PyJWKClient


class StrongJWT:
    """
    Provides a static method to validate a JSON Web Token
    """
    # Determine if string is a URI which should be prohibited:
    @classmethod
    def __is_uri(cls, string_input):

        parsed_result = urllib.parse.urlparse(string_input)
        scheme = parsed_result.scheme

        if "http" in scheme:
            return True

        return False

    # Core JWT validation function against OIDC well-known endpoint:
    @staticmethod
    def validate_jwt(token, aud, iss, well_known_endpoint):
        """
        Validate a JSON Web Token (JWT) against an OpenID Connect (OIDC) well-known endpoint.

        Parameters:
            token (str): The JWT to validate.
            aud (str): The audience of the JWT.
            iss (str): The issuer of the JWT.
            well_known_endpoint (str): The OIDC well-known endpoint.

        Returns:
            string: The decoded JWT payload if the token is validated.
        Raises:
            jsonwebtoken.exceptions.InvalidAlgorithmError: If the algorithm in the JWT header is not in the approved list.
            jsonwebtoken.exceptions.ExpiredSignatureError: If the JWT expiration claim is beyond the current datetime.
            jsonwebtoken.exceptions.InvalidIssuerError: If the passed issuer is not what is contained within the token payload.
            jsonwebtoken.exceptions.InvalidAudienceError: If the passed audience is not what is contained within the token payload.
            requests.exceptions.ConnectionError: If the request to the well-known endpoint fails.
            ValueError: If the JWT is not properly formatted.
        """
        # Approved signature algorithms. A jwt signed with anything but one of these will be rejected:
        approved_algs = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]

        if not StrongJWT.__is_uri(well_known_endpoint):
            raise requests.exceptions.ConnectionError(
                "Invalid value passed for well_known_endpoint URI.")

        try:
            # Attempt to obtain the jwks_uri from the specified OpenID Connect well-known endpoint and
            # log error if URL is inaccessible or deserialization of JWK set fails:
            response = requests.get(well_known_endpoint, timeout=10)
            jsondata = json.loads(response.text)
            jwks_endpoint = jsondata["jwks_uri"]
        except requests.exceptions.ConnectionError:
            request_error_message = "Request to the following URL failed: " + well_known_endpoint
            raise requests.exceptions.ConnectionError(request_error_message)
        except:
            raise ValueError(
                "Unable to deserialize JWK set at the following URL: " + well_known_endpoint)

        # Get header to determine if typ is JWT and if alg is approved:
        try:
            header = jsonwebtoken.get_unverified_header(token)
        except:
            raise ValueError("Unable to decode and deserialize JWT header.")

        # If typ claim does not exist or is not JWT, raise:
        if "typ" in header:
            if html.escape((header["typ"])) != "JWT":
                raise jsonwebtoken.exceptions.InvalidTokenError(
                    "Token is not of typ JWT")
        else:
            raise jsonwebtoken.exceptions.MissingRequiredClaimError(
                "Token is not a valid JWT")

        # Determine if algorithm is RSA and if not, raise exception:
        if "alg" in header:
            if html.escape((header["alg"])) not in approved_algs:
                approved_alg_string = ", ".join(approved_algs)
                raise jsonwebtoken.exceptions.InvalidAlgorithmError(
                    "Unapproved signature algorithm. Approved values are: " + approved_alg_string + ".")
        else:
            raise jsonwebtoken.exceptions.MissingRequiredClaimError(
                "Token header is missing the alg claim.")

        # If kid claim does not exist, has illegal characters, or is a URI, raise:
        if "kid" in header:
            header_kid = header["kid"]
            cleaned_kid = html.escape(header_kid)

            if header_kid != cleaned_kid or StrongJWT.__is_uri(header_kid):
                raise jsonwebtoken.exceptions.InvalidKeyError(
                    "Token kid contains illegal characters")
        else:
            raise jsonwebtoken.exceptions.MissingRequiredClaimError(
                "Token header is missing kid claim.")

        # Attempt to match the JWT against the JWK from discovered from the well-known endpoint based on the kid (key identifier)
        # value in the JWT header:
        try:
            jwkset = PyJWKClient(jwks_endpoint)
            public_key = jwkset.get_signing_key_from_jwt(token).key
        except Exception as ex:
            raise ValueError(ex.args)

        # Validate the token and log errors:
        decoded_and_validated_jwt_payload = ""
        try:
            decoded_and_validated_jwt_payload = jsonwebtoken.decode(token, public_key, algorithms=approved_algs, audience=aud, issuer=iss, options={
                'verify_exp': True, 'verify_signature': True})

            # Determine if exp claim exists as library will not throw if it does not!
            if "exp" not in decoded_and_validated_jwt_payload:
                raise jsonwebtoken.exceptions.ExpiredSignatureError(
                    "JWT is missing expiration (exp) claim from payload.")

            if "iat" not in decoded_and_validated_jwt_payload and "nbf" not in decoded_and_validated_jwt_payload:
                raise jsonwebtoken.exceptions.ImmatureSignatureError(
                    "JWT requires either issued at (iat) or not before (nbf) claims in payload in order to process.")

        except jsonwebtoken.exceptions.InvalidSignatureError:
            raise jsonwebtoken.exceptions.InvalidSignatureError(
                "JWT signature is invalid.")
        except jsonwebtoken.exceptions.ExpiredSignatureError as exp_ex:
            raise jsonwebtoken.exceptions.ExpiredSignatureError(exp_ex.args)
        except jsonwebtoken.exceptions.InvalidIssuerError:
            raise jsonwebtoken.exceptions.InvalidIssuerError(
                "JWT issuer is invalid.")
        except jsonwebtoken.exceptions.InvalidAudienceError:
            raise jsonwebtoken.exceptions.InvalidAudienceError(
                "JWT audience is invalid.")
        except jsonwebtoken.exceptions.ImmatureSignatureError as exp_ex:
            raise jsonwebtoken.exceptions.ImmatureSignatureError(exp_ex.args)
        except Exception as ex:
            raise ValueError(ex.args)

        return decoded_and_validated_jwt_payload
# -------------------------------------------END StrongJWT Class Definition------------------------------------------
