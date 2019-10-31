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

		// throw on invalid bytes
		private static Encoding _encoding = new UTF8Encoding(false, true);

		/// <summary>
		/// Generate a signed request for Duo authentication.
		/// The returned value should be passed into the Duo.init() call
		/// in the rendered web page used for Duo authentication.
		/// </summary>
		/// <param name="ikey">Duo integration key</param>
		/// <param name="skey">Duo secret key</param>
		/// <param name="akey">Application secret key</param>
		/// <param name="username">Primary-authenticated username</param>
		/// <param name="current_time">(optional) The current UTC time</param>
		/// <returns>signed request</returns>
		public static string SignRequest(string ikey, string skey, string akey, string username, DateTime? current_time=null)
		{
			string duo_sig;
			string app_sig;

			DateTime current_time_value = current_time ?? DateTime.UtcNow;

			if (username == "") {
				return ERR_USER;
			}
			if (username.Contains("|")) {
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
				duo_sig = SignVals(skey, username, ikey, DUO_PREFIX, DUO_EXPIRE, current_time_value);
				app_sig = SignVals(akey, username, ikey, APP_PREFIX, APP_EXPIRE, current_time_value);
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
		/// <param name="current_time">(optional) The current UTC time</param>
		/// <returns>authenticated username, or null</returns>
		public static string VerifyResponse(string ikey, string skey, string akey, string sig_response, DateTime? current_time=null)
		{
			string auth_user = null;
			string app_user = null;

			DateTime current_time_value = current_time ?? DateTime.UtcNow;

			try {
				string[] sigs = sig_response.Split(':');
				string auth_sig = sigs[0];
				string app_sig = sigs[1];

				auth_user = ParseVals(skey, auth_sig, AUTH_PREFIX, ikey, current_time_value);
				app_user = ParseVals(akey, app_sig, APP_PREFIX, ikey, current_time_value);
			} catch {
				return null;
			}

			if (auth_user != app_user) {
				return null;
			}

			return auth_user;
		}

		private static string SignVals(string key, string username, string ikey, string prefix, Int64 expire, DateTime current_time)
		{

			Int64 ts = (Int64) (current_time - new DateTime(1970, 1, 1)).TotalSeconds;
			expire = ts + expire;

			string val = username + "|" + ikey + "|" + expire.ToString();
			string cookie = prefix + "|" + Encode64(val);

			string sig = HmacSign(key, cookie);

			return cookie + "|" + sig;
		}

		private static string ParseVals(string key, string val, string prefix, string ikey, DateTime current_time)
		{
			Int64 ts = (int) (current_time - new DateTime(1970, 1, 1)).TotalSeconds;

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
			string u_ikey = cookie_parts[1];
			string expire = cookie_parts[2];

			if (u_ikey != ikey) {
				return null;
			}

			long expire_ts = Convert.ToInt64(expire);
			if (ts >= expire_ts) {
				return null;
			}
				
			return username;
		}

		private static string HmacSign(string skey, string data)
		{
			byte[] key_bytes = _encoding.GetBytes(skey);
			HMACSHA1 hmac = new HMACSHA1(key_bytes);

			byte[] data_bytes = _encoding.GetBytes(data);
			hmac.ComputeHash(data_bytes);

			string hex = BitConverter.ToString(hmac.Hash);
			return hex.Replace("-", "").ToLower();
		}

		private static string Encode64(string plaintext)
		{
			byte[] plaintext_bytes = _encoding.GetBytes(plaintext);
			return System.Convert.ToBase64String(plaintext_bytes);
		}

		private static string Decode64(string encoded)
		{
			byte[] plaintext_bytes = System.Convert.FromBase64String(encoded);
			return _encoding.GetString(plaintext_bytes);
		}
	}
}
