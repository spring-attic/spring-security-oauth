(function(exp, $) {

	var 
		config = {},
		default_lifetime = 3600;


	/*
	 * ------ SECTION: Utilities
	 */

	/*
	 * Returns a random string used for state
	 */
	var uuid = function() {
		return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    		var r = Math.random()*16|0, v = c == 'x' ? r : (r&0x3|0x8);
		    return v.toString(16);
		});
	}

	/* 
	 * Takes an URL as input and a params object.
	 * Each property in the params is added to the url as query string parameters
	 */
	var encodeURL= function(url, params) {
		var res = url;
		var k, i = 0;
		for(k in params) {
			res += (i++ === 0 ? '?' : '&') + encodeURIComponent(k) + '=' + encodeURIComponent(params[k]);
		}
		return res;
	}

	/*
	 * Returns epoch, seconds since 1970.
	 * Used for calculation of expire times.
	 */
	var epoch = function() {
		return Math.round(new Date().getTime()/1000.0);
	}

	/* 
	 * Redirects the user to a specific URL
	 */
	var redirect = function(url) {
		window.location = url;
		// $("body").append('<p><a href="' + url + '">Go here...</a></p>');
	}

	var parseQueryString = function (qs) {
		var e,
			a = /\+/g,  // Regex for replacing addition symbol with a space
			r = /([^&;=]+)=?([^&;]*)/g,
			d = function (s) { return decodeURIComponent(s.replace(a, " ")); },
			q = qs,
			urlParams = {};

		while (e = r.exec(q))
		   urlParams[d(e[1])] = d(e[2]);

		return urlParams;
	}
	/*
	 * ------ / SECTION: Utilities
	 */




	/*
	 * ------ SECTION: Storage for Tokens and state
	 */

	/*
		saveState stores an object with an Identifier.
	TODO: Ensure that both localstorage and JSON encoding has fallbacks for ancient browsers.
	In the state object, we put the request object, plus these parameters:
		  * restoreHash
		  * providerID
		  * scopes

	 */
	var saveState = function(state, obj) {
		// console.log("SaveState (" + state+ ")");
		localStorage.setItem("state-" + state, JSON.stringify(obj));
	};

	/*
	 * getState returns the state object, but also removes it.
	 */
	var getState = function(state) {
		// console.log("getState (" + state+ ")");
		var obj = JSON.parse(localStorage.getItem("state-" + state));
		localStorage.removeItem("state-" + state)
		return obj;
	};



	/*
	 * Checks if a token, has includes a specific scope.
	 * If token has no scope at all, false is returned.
	 */
	var hasScope = function(token, scope) {
		var i;
		if (!token.scopes) return false;
		for(i = 0; i < token.scopes.length; i++) {
			if (token.scopes[i] === scope) return true;
		}
		return false;
	};

	/*
	 * Takes an array of tokens, and removes the ones that
	 * are expired, and the ones that do not meet a scopes requirement.
	 */
	var filterTokens = function(tokens, scopes) {
		var i, j, 
			result = [],
			now = epoch(),
			usethis;

		if (!scopes) scopes = [];

		for(i = 0; i < tokens.length; i++) {
			usethis = true;

			// Filter out expired tokens. Tokens that is expired in 1 second from now.
			if (tokens[i].expires && tokens[i].expires < (now+1)) usethis = false;

			// Filter out this token if not all scope requirements are met
			for(j = 0; j < scopes.length; j++) {
				if (!hasScope(tokens[i], scopes[j])) usethis = false;
			}

			if (usethis) result.push(tokens[i]);
		}
		return result;
	};

	/*
	 * saveTokens() stores a list of tokens for a provider.

		Usually the tokens stored are a plain Access token plus:
		  * expires : time that the token expires
		  * providerID: the provider of the access token?
		  * scopes: an array with the scopes (not string)
	 */
	var saveTokens = function(provider, tokens) {
		// console.log("Save Tokens (" + provider+ ")");
		localStorage.setItem("tokens-" + provider, JSON.stringify(tokens));
	};

	var getTokens = function(provider) {
		// console.log("Get Tokens (" + provider+ ")");
		var tokens = JSON.parse(localStorage.getItem("tokens-" + provider));
		if (!tokens) tokens = [];

		// console.log(tokens)
		return tokens;
	};
	var wipeTokens = function(provider) {
		localStorage.removeItem("tokens-" + provider);
	};
	/*
	 * Save a single token for a provider.
	 * This also cleans up expired tokens for the same provider.
	 */
	var saveToken = function(provider, token) {
		var tokens = getTokens(provider);
		tokens = filterTokens(tokens);
		tokens.push(token);
		saveTokens(provider, tokens);
	};

	/*
	 * Get a token if exists for a provider with a set of scopes.
	 * The scopes parameter is OPTIONAL.
	 */
	var getToken = function(provider, scopes) {
		var tokens = getTokens(provider);
		tokens = filterTokens(tokens, scopes);
		if (tokens.length < 1) return null;
		return tokens[0];
	};
	/*
	 * ------ /SECTION: Storage for Tokens and state
	 */






	/**
	 * Check if the hash contains an access token. 
	 * And if it do, extract the state, compare with
	 * config, and store the access token for later use.
	 */
	var jso_checkfortoken = function() {
		var 
			atoken,
			h = window.location.hash,
			now = epoch(),
			state,
			co;

		/*
		 * Start with checking if there is a token in the hash
		 */
		if (h.length < 2) return;
		if (h.indexOf("access_token") === -1) return;
		h = h.substring(1);
		var atoken = parseQueryString(h);

		if (!atoken.state) return;

		state = getState(atoken.state);
		if (!state) throw "Could not retrieve state";
		if (!state.providerID) throw "Could not get providerid from state";
		if (!config[state.providerID]) throw "Could not retrieve config for this provider.";
		co = config[state.providerID];

		/*
		 * Decide when this token should expire.
		 * Priority fallback:
		 * 1. Access token expires_in
		 * 2. Life time in config (may be false = permanent...)
		 * 3. Specific permanent scope.
		 * 4. Default library lifetime:
		 */
		if (atoken["expires_in"]) {
			atoken["expires"] = now + atoken["expires_in"];
		} else if (co["default_lifetime"] === false) {
			// Token is permanent.
		} else if (co["default_lifetime"]) {
			atoken["expires"] = now + co["default_lifetime"];
		} else if (co["permanent_scope"]) {
			if (!hasScope(atoken, co["permanent_scope"])) {
				atoken["expires"] = now + default_lifetime;
			}
		} else {
			atoken["expires"] = now + default_lifetime;
		}

		/*
		 * Handle scopes for this token
		 */
		if (atoken["scope"]) {
			atoken["scopes"] = atoken["scope"].split(" ");
		} else if (state["scopes"]) {
			atoken["scopes"] = state["scopes"];
		}


		saveToken(state.providerID, atoken);

		if (state.restoreHash) {
			window.location.hash = state.restoreHash;
		} else {
			window.location.hash = '';
		}

		// console.log(atoken);
	}

	/*
	 * A config object contains:
	 */
	var jso_authrequest = function(providerid, scopes) {

		var 
			state,
			request,
			authurl,
			co;

		if (!config[providerid]) throw "Could not find configuration for provider " + providerid;
		co = config[providerid];

		// console.log("About to send an authorization request to [" + providerid + "]. Config:")
		// console.log(co);

		state = uuid();
		request = {
			"response_type": "token"
		};
		request.state = state;


		if (co["redirect_uri"]) {
			request["redirect_uri"] = co["redirect_uri"];
		}
		if (co["client_id"]) {
			request["client_id"] = co["client_id"];
		}
		if (scopes) {
			request["scope"] = scopes.join(" ");
		}

		authurl = encodeURL(co.authorization, request);

		// We'd like to cache the hash for not loosing Application state. 
		// With the implciit grant flow, the hash will be replaced with the access
		// token when we return after authorization.
		if (window.location.hash) {
			request["restoreHash"] = window.location.hash;
		}
		request["providerID"] = providerid;
		if (scopes) {
			request["scopes"] = scopes;
		}

		// console.log("Saving state [" + state+ "]");
		// console.log(JSON.parse(JSON.stringify(request)));
		saveState(state, request);
		redirect(authurl);

	};

	exp.jso_ensureTokens = function (ensure) {
		var providerid, scopes, token;
		for(providerid in ensure) {
			scopes = undefined;
			if (ensure[providerid]) scopes = ensure[providerid];
			token = getToken(providerid, scopes);

			// console.log("Ensure token for provider [" + providerid + "] ");
			// console.log(token);

			if (token === null) {
				jso_authrequest(providerid, scopes);
			}
		}
		return true;
	}


	exp.jso_configure = function(c) {
		config = c;
		try {
			jso_checkfortoken();	
		} catch(e) {
			console.log("Error when retrieving token from hash: " + e);
			window.location.hash = "";
		}
		
	}

	exp.jso_dump = function() {
		var key;
		for(key in config) {
			console.log("=====> Processing provider [" + key + "]");
			console.log("=] Config");
			console.log(config[key]);
			console.log("=] Tokens")
			console.log(getTokens(key));
		}
	}

	exp.jso_wipe = function() {
		var key;
		for(key in config) {
			wipeTokens(key);
		}
	}

	exp.jso_getToken = function(providerid, scopes) {
		var token = getToken(providerid, scopes);
		if (!token) return null;
		if (!token["access_token"]) return null;
		return token["access_token"];
	}

	$.oajax = function(settings) {
		var 
			allowia,
			scopes,
			token,
			providerid,
			co;
		
		providerid = settings.jso_provider;
		allowia = settings.jso_allowia || false;
		scopes = settings.jso_scopes;
		token = getToken(providerid, scopes);
		co = config[providerid];

		if (!token) {
			if (allowia) {
				jso_authrequest(providerid, scopes);
				return;
			} else {
				throw "Could not perform AJAX call because no valid tokens was found.";	
			}
		}

		if (co["presenttoken"] && co["presenttoken"] === "qs") {
			// settings.url += ((h.indexOf("?") === -1) ? '?' : '&') + "access_token=" + encodeURIComponent(token["access_token"]);
			if (!settings.data) settings.data = {};
			settings.data["access_token"] = token["access_token"];
		} else {
			if (!settings.headers) settings.headers = {};
			settings.headers["Authorization"] = "Bearer " + token["access_token"];
		}

		$.ajax(settings);

	};


})(window, jQuery);