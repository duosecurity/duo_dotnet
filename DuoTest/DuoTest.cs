/*
 * DuoTest.cs
 *
 * Copyright (c) 2011 Duo Security
 * All rights reserved, all wrongs reversed.
 *
 * Simple test exercising the Duo Web SDK
 */

using System;
using System.Collections;
using System.Linq;
using System.Text;

using Duo;

namespace DuoTest
{
	class DuoTest
	{
		/* Dummy IKEY and SKEY values */
		const string IKEY = "DIXXXXXXXXXXXXXXXXXX";
		const string SKEY = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
		const string AKEY = "useacustomerprovidedapplicationsecretkey";

		/* Dummy username */
		const string USER = "testuser";

		/* Dummy response signatures */
		const string INVALID_RESPONSE = "AUTH|INVALID|SIG";
		const string EXPIRED_RESPONSE = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTMwMDE1Nzg3NA==|cb8f4d60ec7c261394cd5ee5a17e46ca7440d702";
		const string FUTURE_RESPONSE = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0Mw==|d20ad0d1e62d84b00a3e74ec201a5917e77b6aef";

		static void Main(string[] args)
		{
			string request_sig;

			request_sig = Duo.Web.SignRequest(IKEY, SKEY, AKEY, USER);
			if (request_sig == null) {
				Console.WriteLine("did not generate signed request.");
			}

			request_sig = Duo.Web.SignRequest(IKEY, SKEY, AKEY, "");
			if (request_sig != Duo.Web.ERR_USER) {
				Console.WriteLine("did not catch username error.");
			}

			request_sig = Duo.Web.SignRequest("invalid", SKEY, AKEY, USER);
			if (request_sig != Duo.Web.ERR_IKEY) {
				Console.WriteLine("did not catch ikey error.");
			}

			request_sig = Duo.Web.SignRequest(IKEY, "invalid", AKEY, USER);
			if (request_sig != Duo.Web.ERR_SKEY) {
				Console.WriteLine("did not catch skey error.");
			}

			request_sig = Duo.Web.SignRequest(IKEY, SKEY, "invalid", USER);
			if (request_sig != Duo.Web.ERR_AKEY) {
				Console.WriteLine("did not catch akey error.");
			}

			/*******************************************************************/

			string[] sigs;
			string valid_app_sig, invalid_app_sig;
			string invalid_user, expired_user, future_user;

			request_sig = Duo.Web.SignRequest(IKEY, SKEY, AKEY, USER);
			sigs = request_sig.Split(':');
			valid_app_sig = sigs[1];

			request_sig = Duo.Web.SignRequest(IKEY, SKEY, "invalidinvalidinvalidinvalidinvalidinvalid", USER);
			sigs = request_sig.Split(':');
			invalid_app_sig = sigs[1];

			invalid_user = Duo.Web.VerifyResponse(IKEY, SKEY, AKEY, INVALID_RESPONSE + ":" + valid_app_sig);
			if (invalid_user != null) {
				Console.WriteLine("failed invalid user verify test.");
			}

			expired_user = Duo.Web.VerifyResponse(IKEY, SKEY, AKEY, EXPIRED_RESPONSE + ":" + valid_app_sig);
			if (expired_user != null) {
				Console.WriteLine("failed expired user verify test.");
			}

			future_user = Duo.Web.VerifyResponse(IKEY, SKEY, AKEY, FUTURE_RESPONSE + ":" + invalid_app_sig);
			if (future_user != null) {
				Console.WriteLine("failed future user invalid app sig test.");
			}

			future_user = Duo.Web.VerifyResponse(IKEY, SKEY, AKEY, FUTURE_RESPONSE + ":" + valid_app_sig);
			if (future_user != USER) {
				Console.WriteLine("failed future user valid app sig test.");
			}

			Console.WriteLine("test cases completed.");
		}
	}
}
