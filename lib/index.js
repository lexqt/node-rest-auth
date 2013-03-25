var crypto = require('crypto');


// ------------------------------------------------------------------
//  Permissions middleware

exports.requirePerms = function(perms, checkPermissions) {
	if (perms && ! Array.isArray(perms)) {
		perms = [ perms ];
	}
	return function(req, res, next) {
		// Check authentication
		if (! req.user) {
			return sendUnauthorizedError(res, 'Must be authenticated to make that request');
		}
		if (! perms) {
			next();
		}
		// Check for the requested permissions
		else {
			checkPermissions(req.user, perms, function(err, isAuthorized) {
				if (err) {
					return next(err);
				}
				if (! isAuthorized) {
					return res.json({ error: 'Not authorized to make that request' }, 403);
				}
				next();
			});
		}
	};
};

// ------------------------------------------------------------------
//  Main authentication middleware

exports.authenticate = function(options) {
	options = options || {};
	// Default options
	var defaultOptions = {
		authenticateUser: null,
		getUser: null,
		getUserCredentials: getUserCredentials,
		populateUsernameOnly: true,
		maxAge: 7200000, // 2 hours
		authRoute: '/auth-token',
		authParam: 'authToken',
		authCookie: 'authToken',
		httpOnlyCookie: true,
		secureCookie: false,
		autoRenewToken: true, // true, false, or "cookie-only"
		algorithm: 'sha256',
		secretKey: null,
		salt: null,
	};
	Object.keys(defaultOptions).forEach(function(key) {
		if (! options.hasOwnProperty(key)) {
			options[key] = defaultOptions[key];
		}
	});
	if ('function' !== typeof options.authenticateUser) {
		throw new Error('"authenticateUser" function must be defined');
	}
	if ('function' !== typeof options.getUser) {
		throw new Error('"getUser" function must be defined');
	}
	if (! options.secretKey) {
		throw new Error('"secretKey" must be defined');
	}
	// Generate salt if not provided
	if (! options.salt) {
		var salt = generateSalt();
	}
	// Get utility functions
	var buildHmac = saltedHmacBuilder(options.algorithm, options.secretKey);
	var buildAuthToken = authTokenBuilder(buildHmac, salt, !options.salt);
	if (options.authCookie) {
		var writeCookie = cookieWriterBuilder(options);
	}
	// The actual middleware function
	return function(req, res, next) {
		// Handle authentication token requests
		if (req.path === options.authRoute) {
			if (req.method === 'POST') {
				// Authenticate the user data using the method provided
				options.authenticateUser(req,
					function(err, user, authFailureMsg) {
						if (err) {return next(err);}
						if (! user) {
							return sendUnauthorizedError(res, authFailureMsg);
						}
						var creds = options.getUserCredentials(user);
						// Populate the user property
						req.user = options.populateUsernameOnly ?
										creds.username : user;
						// Create the authentication token
						var timestamp = Date.now() + options.maxAge;
						var authToken = buildAuthToken(creds.username, creds.secret, timestamp);
						// Set an authentication cookie if needed
						if (options.authCookie) {
							writeCookie(res, authToken, timestamp);
						}
						res.json({ authToken: authToken });
					}
				);
			} else {
				res.json({ error: options.authRoute + ' only supports POST requests' }, 405);
			}
		}
		// Authenticate other requests
		else {
			var authToken;
			// Check for an auth token cookie
			if (options.authCookie && req.cookies[options.authCookie]) {
				authToken = req.cookies[options.authCookie];
			} else if (options.authParam) {
				// Check for an auth token in the query string
				if (req.query[options.authParam]) {
					authToken = req.query[options.authParam];
				}
				// Check for an auth token in the request body
				else if (req.body[options.authParam]) {
					authToken = req.body[options.authParam];
				}
			}
			// Parse the auth token
			if (! authToken) {
				req.user = null;
				return next();
			}

			authToken = parseAuthToken(authToken);
			if (! authToken) {
				return sendUnauthorizedError(res);
			}

			options.getUser(authToken.username,
				function(err, user) {
					if (err) {
						return next(err);
					}
					if (! user) {
						return sendUnauthorizedError(res);
					}
					var creds = options.getUserCredentials(user);
					// Check the auth token
					var _salt = authToken.salt || salt;
					var hash = generateHash(buildHmac, _salt,
											creds.username, creds.secret,
											authToken.timestamp);
					if (hash !== authToken.hash) {
						return sendUnauthorizedError(res);
					}
					if (Date.now() > authToken.timestamp) {
						return sendUnauthorizedError(res, 'Expired auth token');
					}
					// Populate the user property
					req.user = options.populateUsernameOnly ?
									creds.username : user;
					next();
				}
			);

		}
	};
};

// ------------------------------------------------------------------
//  Utilities

// Generate random salt
function generateSalt() {
	var h = crypto.createHash('sha1');
	h.end(crypto.randomBytes(7));
	return h.read().toString('hex', 0, 3);
}

// Get auth data from user model
function getUserCredentials(user) {
	return {
		username: user.username,
		secret: user.password
	}
}

// Get new Hmac instance builder
function saltedHmacBuilder(algorithm, key) {
	return function(salt) {
		var h = crypto.createHash('sha1');
		h.end(salt + key);
		var newKey = h.read().toString('hex');
		return crypto.createHmac(algorithm, newKey);
	}
}

function generateHash(buildHmac, salt, username, secret, timestamp) {
	var hmac = buildHmac(salt);
	hmac.end(username + secret + timestamp);
	return hmac.read().toString('base64');
}

// Build an authentication token from components
function authTokenBuilder(buildHmac, salt, includeSalt) {
	return function(username, secret, timestamp) {
		var hash = generateHash(buildHmac, salt, username, secret, timestamp);
		var parts = includeSalt ?
						[username, timestamp, salt, hash] :
						[username, timestamp, hash];
		return parts.join(':');
	};
}

// Parse an auth token into an object
function parseAuthToken(token) {
	token = token.split(':');
	var len = token.length;
	if (len < 3 || 4 > len) {
		return false;
	};
	var res = {
		username: token[0],
	};
	try {
		res.timestamp = parseInt(token[1], 10);
	} catch (e) {
		return false;
	}
	if (len === 3) {
		res.hash = token[2];
	} else {
		// len === 4
		res.salt = token[2];
		res.hash = token[3];
	}
	return res;
}

// Get a cookie writing function
function cookieWriterBuilder(opts) {
	return function(res, token, timestamp) {
		res.cookie(opts.authCookie, token, {
			expires: new Date(timestamp),
			httpOnly: opts.httpOnlyCookie,
			secure: opts.secureCookie
		});
	};
}

function sendUnauthorizedError(res, msg) {
	res.set('WWW-Authenticate', 'Token');
	res.json({ error: msg || 'Bad auth token' }, 401);
}

/* End of file index.js */
/* Location: ./lib/index.js */
