/*
 * DuoWeb.cs
 *
 * Copyright (c) 2011 Duo Security
 * All rights reserved, all wrongs reversed.
 */

using System;
using System.IO;
using System.Net;
using System.Web;
using System.Text;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Duo
{
	public static class Web
	{
		const string DUO_PREFIX = "TX";
		const string APP_PREFIX = "APP";
		const string AUTH_PREFIX = "AUTH";

		const int DUO_EXPIRE = 300;
		const int APP_EXPIRE = 3600;

		const int IKEY_LEN = 20;
		const int SKEY_LEN = 40;
		const int AKEY_LEN = 40;

		public static string ERR_USER = "ERR|The username passed to sign_request() is invalid.";
		public static string ERR_IKEY = "ERR|The Duo integration key passed to sign_request() is invalid.";
		public static string ERR_SKEY = "ERR|The Duo secret key passed to sign_request() is invalid.";
		public static string ERR_AKEY = "ERR|The application secret key passed to sign_request() must be at least 40 characters.";
		public static string ERR_UNKNOWN = "ERR|An unknown error has occurred.";

		/// <summary>
		/// Generate a signed request for Duo authentication.
		/// The returned value should be passed into the Duo.init() call
		/// in the rendered web page used for Duo authentication.
		/// </summary>
		/// <param name="ikey">Duo integration key</param>
		/// <param name="skey">Duo secret key</param>
		/// <param name="akey">Application secret key</param>
		/// <param name="username">Primary-authenticated username</param>
		/// <returns>signed request</returns>
		public static string SignRequest(string ikey, string skey, string akey, string username)
		{
			string duo_sig;
			string app_sig;

			if (username == "") {
				return ERR_USER;
			}
			if (ikey.Length != IKEY_LEN) {
				return ERR_IKEY;
			}
			if (skey.Length != SKEY_LEN) {
				return ERR_SKEY;
			}
			if (akey.Length < AKEY_LEN) {
				return ERR_AKEY;
			}

			try {
				duo_sig = SignVals(skey, username, ikey, DUO_PREFIX, DUO_EXPIRE);
				app_sig = SignVals(akey, username, ikey, APP_PREFIX, APP_EXPIRE);
			} catch {
				return ERR_UNKNOWN;
			}

			return duo_sig + ":" + app_sig;
		}

		/// <summary>
		/// Validate the signed response returned from Duo.
		/// Returns the username of the authenticated user, or null.
		/// </summary>
		/// <param name="ikey">Duo integration key</param>
		/// <param name="skey">Duo secret key</param>
		/// <param name="akey">Application secret key</param>
		/// <param name="sig_response">The signed response POST'ed to the server</param>
		/// <returns>authenticated username, or null</returns>
		public static string VerifyResponse(string ikey, string skey, string akey, string sig_response)
		{
			string auth_user = null;
			string app_user = null;

			try {
				string[] sigs = sig_response.Split(':');
				string auth_sig = sigs[0];
				string app_sig = sigs[1];

				auth_user = ParseVals(skey, auth_sig, AUTH_PREFIX);
				app_user = ParseVals(akey, app_sig, APP_PREFIX);
			} catch {
				return null;
			}

			if (auth_user != app_user) {
				return null;
			}

			return auth_user;
		}

		private static string SignVals(string key, string username, string ikey, string prefix, int expire)
		{
			int ts = (int) (DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
			expire = ts + expire;

			string val = username + "|" + ikey + "|" + expire.ToString();
			string cookie = prefix + "|" + Encode64(val);

			string sig = HmacSign(key, cookie);

			return cookie + "|" + sig;
		}

		private static string ParseVals(string key, string val, string prefix)
		{
			int ts = (int) (DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;

			string[] parts = val.Split('|');
			if (parts.Length != 3) {
				return null;
			}

			string u_prefix = parts[0];
			string u_b64 = parts[1];
			string u_sig = parts[2];

			string sig = HmacSign(key, u_prefix + "|" + u_b64);
			if (HmacSign(key, sig) != HmacSign(key, u_sig)) {
				return null;
			}

			if (u_prefix != prefix) {
				return null;
			}

			string cookie = Decode64(u_b64);
			string[] cookie_parts = cookie.Split('|');
			if (cookie_parts.Length != 3) {
				return null;
			}

			string username = cookie_parts[0];
			string ikey = cookie_parts[1];
			string expire = cookie_parts[2];

			int expire_ts = Convert.ToInt32(expire);
			if (ts >= expire_ts) {
				return null;
			}
				
			return username;
		}

		private static string HmacSign(string skey, string data)
		{
			byte[] key_bytes = ASCIIEncoding.ASCII.GetBytes(skey);
			HMACSHA1 hmac = new HMACSHA1(key_bytes);

			byte[] data_bytes = ASCIIEncoding.ASCII.GetBytes(data);
			hmac.ComputeHash(data_bytes);

			string hex = BitConverter.ToString(hmac.Hash);
			return hex.Replace("-", "").ToLower();
		}

		private static string Encode64(string plaintext)
		{
			byte[] plaintext_bytes = ASCIIEncoding.ASCII.GetBytes(plaintext);
			string encoded = System.Convert.ToBase64String(plaintext_bytes);
			return encoded;
		}

		private static string Decode64(string encoded)
		{
			byte[] plaintext_bytes = System.Convert.FromBase64String(encoded);
			string plaintext = ASCIIEncoding.ASCII.GetString(plaintext_bytes);
			return plaintext;
		}
	}
}
