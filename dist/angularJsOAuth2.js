'use strict';

(function () {
        
    angular.module('oauth2.services',[]).service('tokenService',['$window',function($window){
        this.expired=function(token){
            return (token && token.expires_at && new Date(token.expires_at) < new Date());
        };
        this.getSessionToken= function() {
            var tokenString = this.tokenStorage.get($window);
            var token = null;
            if (tokenString && tokenString !== "null") {
                token = JSON.parse(tokenString);
                token.expires_at = new Date(token.expires_at);
            }
            return token;
        };
        this.tokenStorage = {
            get: function () { return $window.sessionStorage.getItem('token') },
            set: function (token) { $window.sessionStorage.setItem('token', token); },
            clear: function () { $window.sessionStorage.removeItem('token'); }
        };
    }]);

    angular.module('oauth2.accessToken', []).factory('AccessToken', ['$rootScope', '$location', '$window','tokenService', function ($rootScope, $location, $window,tokenService) {
        var service = {
            token: null
        };
        var oAuth2HashParams = ['id_token', 'access_token', 'token_type', 'expires_in', 'scope', 'state', 'error', 'error_description'];

        function setExpiresAt(token) {
            if (token) {
                var expires_at = new Date();
                expires_at.setSeconds(expires_at.getSeconds() + parseInt(token.expires_in) - 60); // 60 seconds less to secure browser and response latency
                token.expires_at = expires_at;
            }
        }

        function setTokenFromHashParams(hash) {
            var token = getTokenFromHashParams(hash);
            if (token !== null) {
                setExpiresAt(token);
                tokenService.tokenStorage.set(JSON.stringify(token), $window)
            }
            return token;
        }

        function getTokenFromHashParams(hash) {
            var token = {};
            var regex = /([^&=]+)=([^&]*)/g;
            var m;

            while (m = regex.exec(hash)) {
                var param = decodeURIComponent(m[1]);
                var value = decodeURIComponent(m[2]);

                if (oAuth2HashParams.indexOf(param) >= 0) {
                    token[param] = value;
                }
            }

            if ((token.access_token && token.expires_in) || token.error) {
                return token;
            }
            return null;
        }

        service.get = function () {
            return this.token;
        };
        service.set = function (trustedTokenHash) {
            // Get and scrub the session stored state
            var parsedFromHash = false;
            var previousState = $window.sessionStorage.getItem('verifyState');
            $window.sessionStorage.setItem('verifyState', null);

            if (trustedTokenHash) {
                // We 'trust' this hash as it was already 'parsed' by the child iframe before we got it as the parent
                // and then handed it back (not just reverifying as the sessionStorage was blanked by the child frame, so
                // we can't :(
                service.token = setTokenFromHashParams(trustedTokenHash);
            }
            else if ($location.$$html5) {
                if ($location.path().length > 1) {
                    var values = $location.path().substring(1);
                    service.token = setTokenFromHashParams(values);
                    if (service.token) {
                        parsedFromHash = true;
                    }
                }
            } else {
                // Try and get the token from the hash params on the URL
                var hashValues = window.location.hash;
                if (hashValues.length > 0) {
                    if (hashValues.indexOf('#/') == 0) {
                        hashValues = hashValues.substring(2);
                    }
                    service.token = setTokenFromHashParams(hashValues);
                    if (service.token) {
                        parsedFromHash = true;
                    }
                }
            }

            if (service.token === null) {
                service.token = tokenService.getSessionToken($window);
                if (service.token === undefined) {
                    service.token = null;
                }
            }

            if (service.token && service.token.error) {
                var error = service.token.error;
                service.destroy();
                $rootScope.$broadcast('oauth2:authError', error);
            }

            if (service.token !== null) {
                if (!parsedFromHash || previousState == service.token.state) {
                    $rootScope.$broadcast('oauth2:authSuccess', service.token);
                    var oauthRedirectRoute = $window.sessionStorage.getItem('oauthRedirectRoute');
                    if (typeof (oauthRedirectRoute) !== 'undefined' && oauthRedirectRoute != "null") {
                        $window.sessionStorage.setItem('oauthRedirectRoute', null);
                        $location.path(oauthRedirectRoute);
                    }
                }
                else {
                    service.destroy();
                    $rootScope.$broadcast('oauth2:authError', 'Suspicious callback');
                }
            }


            return service.token;
        };
        service.destroy = function () {
            tokenService.tokenStorage.clear($window)
            $window.sessionStorage.setItem('token', null);
            service.token = null;
        };

        return service;
    }]);

    // Auth interceptor - if token is missing or has expired this broadcasts an authRequired event
    angular.module('oauth2.interceptor', []).factory('OAuth2Interceptor', ['$rootScope', '$q', '$window','tokenService', function ($rootScope, $q, $window,tokenService) {

        var service = {
            request: function (config) {
                var token = tokenService.getSessionToken($window);
                if (tokenService.expired(token)) {
                    $rootScope.$broadcast('oauth2:authExpired', token);
                }
                else if (token) {
                    config.headers.Authorization = 'Bearer ' + token.access_token;
                    return config;
                }
                return config;
            },
            response: function (response) {
                var token = tokenService.getSessionToken($window);
                if (response.status === 401) {
                    if (tokenService.expired(token)) {
                        $rootScope.$broadcast('oauth2:authExpired', token);
                    } else {
                        $rootScope.$broadcast('oauth2:unauthorized', token);
                    }
                }
                else if (response.status === 500) {
                    $rootScope.$broadcast('oauth2:internalservererror');
                }
                return response;
            },
            responseError: function (response) {
                var token = tokenService.getSessionToken($window);
                if (response.status === 401) {
                    if (tokenService.expired(token)) {
                        $rootScope.$broadcast('oauth2:authExpired', token);
                    } else {
                        $rootScope.$broadcast('oauth2:unauthorized', token);
                    }
                }
                else if (response.status === 500) {
                    $rootScope.$broadcast('oauth2:internalservererror');
                }
                return $q.reject(response);
            }
        };
        return service;
    }]);

    // Endpoint wrapper
    angular.module('oauth2.endpoint', ['angular-md5']).provider('Endpoint',function () {
        var settings={            
        };
        this.setOptions = function (options) {            
            angular.extend(settings, options);            
        };
        this.$get=['AccessToken', '$window', 'md5', '$rootScope','tokenService','$location',function(accessToken, $window, md5, $rootScope,tokenService,$location){
                var service = {
                    authorize: function () {
                        accessToken.destroy();
                        $window.sessionStorage.setItem('verifyState', settings.state);
                        window.location.replace(getAuthorizationUrl());
                    },
                    appendSignoutToken: false
                };
                if (!settings.nonce && settings.autoGenerateNonce) {
                    settings.nonce = generateState();
                }            
                settings.state = settings.state || generateState();                

                function getAuthorizationUrl(performSilently) {
                    var url = settings.authorizationUrl + '?' +
                                    'client_id=' + encodeURIComponent(settings.clientId) + '&' +
                                    'redirect_uri=' + encodeURIComponent(performSilently ? settings.silentTokenRedirectUrl : settings.redirectUrl) + '&' +
                                    'response_type=' + encodeURIComponent(settings.responseType) + '&' +
                                    'scope=' + encodeURIComponent(settings.scope);
                    if (settings.nonce) {
                        url += '&nonce=' + encodeURIComponent(settings.nonce);
                    }
                    url += '&state=' + encodeURIComponent(settings.state);

                    if (performSilently) {
                        url = url + "&prompt=none";
                    }
                    return url;
                }
                function generateState() {
                    var text = ((Date.now() + Math.random()) * Math.random()).toString().replace(".", "");
                    return md5.createHash(text);
                }    
                service.renewTokenSilently = function () {
                    function setupTokenSilentRenewInTheFuture() {
                        var frame = $window.document.createElement("iframe");
                        frame.style.display = "none";
                        $window.sessionStorage.setItem('verifyState', settings.state);
                        frame.src = getAuthorizationUrl(true);
                        function cleanup() {
                            $window.removeEventListener("message", message, false);
                            if (handle) {
                                window.clearTimeout(handle);
                            }
                            handle = null;
                            $window.setTimeout(function () {
                                // Complete this on another tick of the eventloop to allow angular (in the child frame) to complete nicely.
                                $window.document.body.removeChild(frame);
                            }, 0);
                        }

                        function message(e) {
                            if (handle && e.origin === location.protocol + "//" + location.host && e.source == frame.contentWindow) {
                                cleanup();
                                if (e.data === "oauth2.silentRenewFailure") {
                                    $rootScope.$broadcast('oauth2:authExpired');
                                }
                                else {
                                    accessToken.set(e.data);
                                }
                            }
                        }

                        var handle = window.setTimeout(function () {
                            cleanup();
                        }, 5000);
                        $window.addEventListener("message", message, false);
                        $window.document.body.appendChild(frame);
                    };

                    var now = new Date();
                    // Renew the token 1 minute before we expect it to expire. N.B. This code elsewhere sets the expires_at to be 60s less than the server-decided expiry time
                    // this has the effect of reducing access token lifetimes by a mininum of 2 minutes, and restricts you to producing access tokens that are at *least* this long lived

                    var renewTokenAt = new Date(accessToken.get().expires_at.getTime() - 60000);
                    var renewTokenIn = renewTokenAt - new Date();
                    window.setTimeout(setupTokenSilentRenewInTheFuture, renewTokenIn);
                };

                service.signOut = function (token) {
                    if (settings.signOutUrl && settings.signOutUrl.length > 0) {
                        var url = settings.signOutUrl;
                        if (settings.appendSignoutToken) {
                            url = url + '?id_token_hint=' + token;
                        }
                        if (settings.signOutRedirectUrl && settings.signOutRedirectUrl.length > 0) {
                            url = url + (settings.appendSignoutToken ? '&' : '?');
                            url = url + 'post_logout_redirect_uri=' + encodeURIComponent(settings.signOutRedirectUrl);
                        }
                        window.location.replace(url);
                    }
                };

                service.init = function (params) {     
                    if (!params.nonce && params.autoGenerateNonce) {
                        params.nonce = generateState();
                    }
                    settings.nonce = params.nonce||settings.nonce;
                    settings.clientId = params.clientId||settings.clientId;
                    settings.redirectUrl = params.redirectUrl||settings.redirectUrl;
                    settings.scope = params.scope||settings.scope;
                    settings.responseType = params.responseType||settings.responseType;
                    settings.authorizationUrl = params.authorizationUrl||settings.authorizationUrl;
                    settings.signOutUrl = params.signOutUrl||settings.signOutUrl;
                    settings.silentTokenRedirectUrl = params.silentTokenRedirectUrl||settings.silentTokenRedirectUrl;
                    settings.signOutRedirectUrl = params.signOutRedirectUrl||settings.signOutRedirectUrl;
                    settings.state = params.state || settings.state;
                    if (params.signOutAppendToken == 'true') {
                        settings.appendSignoutToken = true;
                    }
                };
                service.getSettings=function(){
                    return settings;                    
                };
                service.doAuth=function(event){
                    if (!accessToken.get() || tokenService.expired(accessToken.get())) {
		                event.preventDefault();
		                $window.sessionStorage.setItem('oauthRedirectRoute', $location.path());
		                service.authorize();
		            }                    
                };
                return service;            
        }];
    });

    // Open ID directive
    angular.module('oauth2.directive', [])
		.config(['$routeProvider', function ($routeProvider) {
		    $routeProvider
				.when('/silent-renew', {
				    template: ""
				})
		}])
		.directive('oauth2', ['$rootScope', '$http', '$window', '$location', '$templateCache', '$compile', '$parse', 'AccessToken', 'Endpoint','tokenService', function ($rootScope, $http, $window, $location, $templateCache, $compile, $parse, accessToken, endpoint,tokenService) {
		    var definition = {
		        restrict: 'E',
		        replace: true,
		        scope: {
		            authorizationUrl: '@',          // authorization server url
		            clientId: '@',       			// client ID
		            redirectUrl: '@',   			// uri th auth server should redirect to (cannot contain #)
		            responseType: '@',  			// defaults to token
		            scope: '@',						// scopes required (not the Angular scope - the auth server scopes)
		            state: '@',						// state to use for CSRF protection
		            template: '@',					// path to a replace template for the button, defaults to the one supplied by bower
		            buttonClass: '@',				// the class to use for the sign in / out button - defaults to btn btn-primary
		            signInText: '@',				// text for the sign in button
		            signOutText: '@',				// text for the sign out button
		            signOutUrl: '@',				// url on the authorization server for logging out. Local token is deleted even if no URL is given but that will leave user logged in against STS
		            signOutAppendToken: '@',		// defaults to 'false', set to 'true' to append the token to the sign out url
		            signOutRedirectUrl: '@',		// url to redirect to after sign out on the STS has completed
		            silentTokenRedirectUrl: '@',	// url to use for silently renewing access tokens, default behaviour is not to do
		            nonce: '@?',					// nonce value, optional. If unspecified or an empty string and autoGenerateNonce is true then a nonce will be auto-generated
		            autoGenerateNonce: '=?',	    // Should a nonce be autogenerated if not supplied. Optional and defaults to true.
		            tokenStorageHandler: '=',		            
		            userInfoUrl: '@'                // UserInfo endpoint. If this value is provided, upon successful authorization, a request will be made to the userInfo endpoint with the access_token. The result will be available as $rootScope.oauth2User
		        }
		    };

		    definition.link = function (scope, element, attrs) {
		        function compile() {
		            var tpl = '<p class="navbar-btn"><a class="{{buttonClass}}" ng-click="signedIn ? signOut() : signIn()"><span href="#" ng-hide="signedIn">{{signInText}}</span><span href="#" ng-show="signedIn">{{signOutText}}</span></a></p>';
		            if (scope.template && (scope.template.length == 0 || scope.template.toLowerCase() == 'none')) {
		                element.html('<span></span>');
		                $compile(element.contents())(scope);
		            }
		            else if (scope.template) {
		                $http.get(scope.template, { cache: $templateCache }).success(function (html) {
		                    element.html(html);
		                    $compile(element.contents())(scope);
		                });
		            } else {
		                element.html(tpl);
		                $compile(element.contents())(scope);
		            }
		        };		        
                var endpointSettings= endpoint.getSettings();
		        function routeChangeHandler(event, nextRoute) {
		            if (nextRoute.$$route && nextRoute.$$route.requireToken) {
		                endpoint.doAuth(event);
		            }
		        };		        

		        function init() {
		            if (scope.tokenStorageHandler) {
		                tokenService.tokenStorage = scope.tokenStorageHandler
		            }
		            scope.buttonClass = scope.buttonClass || 'btn btn-primary';
		            scope.signInText = scope.signInText || 'Sign In';
		            scope.signOutText = scope.signOutText || 'Sign Out';
		            scope.responseType = scope.responseType || 'token';
		            scope.signOutUrl = scope.signOutUrl || '';
		            scope.signOutRedirectUrl = scope.signOutRedirectUrl || '';
		            scope.unauthorizedAccessUrl = scope.unauthorizedAccessUrl || '';
                    scope.unauthorizedAccessState = scope.unauthorizedAccessState || '';
		            scope.silentTokenRedirectUrl = scope.silentTokenRedirectUrl || '';
		            if (scope.autoGenerateNonce === undefined) {
		                scope.autoGenerateNonce = true;
		            }
		            compile();

		            endpoint.init(scope);
		            scope.$on('oauth2:authRequired', function () {
		                endpoint.authorize();
		            });	
		            $rootScope.signedIn = accessToken.set() !== null;
		            $rootScope.$on('$routeChangeStart', routeChangeHandler);                    
		            
		        }

		        scope.$watch('clientId', function (value) {
                    if(value){
                        init();                        
                    }                     
                });

		        $rootScope.signedIn = false;

		        scope.signIn = function () {
		            $window.sessionStorage.setItem('oauthRedirectRoute', $location.path());
		            endpoint.authorize();
		        }

		        scope.signOut = function () {
		            var token = accessToken.get().id_token;
		            accessToken.destroy();
		            endpoint.signOut(token);
		        };
		    };

		    return definition;
		}]);

    // App libraries
    angular.module('afOAuth2', [
      'oauth2.services',       // oauth2 services
      'oauth2.directive',      // login directive
      'oauth2.accessToken',    // access token service
      'oauth2.endpoint',       // oauth endpoint service
      'oauth2.interceptor'     // bearer token interceptor
    ]).config(['$locationProvider', '$httpProvider',
        function ($locationProvider, $httpProvider) {
            $httpProvider.interceptors.push('OAuth2Interceptor');
        }
    ]).run(["$rootScope", "Endpoint","AccessToken","$location","$window","$state",function($rootScope,Endpoint,AccessToken,$location,$window,$state){
            var endpointSettings = Endpoint.getSettings();            
            $rootScope.$on("$stateChangeStart", function (event, toState) {
                if (toState.name!=endpointSettings.unauthorizedAccessState &&
                    (toState && toState.data && toState.data.requireToken)) {
                    Endpoint.doAuth(event);
                }
            });
            $rootScope.$on('oauth2:authSuccess', function () {
                if (endpointSettings.silentTokenRedirectUrl && endpointSettings.silentTokenRedirectUrl.length > 0) {
                    if ($location.path().indexOf("/silent-renew") == 0) {
                        // A 'child' frame has successfully authorised an access token.
                        if ($window.window.top && $window.window.parent && $window.window !== $window.window.top) {
                            var hash = hash || $window.window.location.hash;
                            if (hash) {
                                $window.window.parent.postMessage(hash, $location.protocol() + "//" + $location.host());
                            }
                        }
                    } else {
                        // An 'owning' frame has successfully authorised an access token.
                        Endpoint.renewTokenSilently();
                    }
                }

                if (endpointSettings.userInfoUrl && scope.userInfoUrl.length > 0) {
                    var userInfoUrl = endpointSettings.userInfoUrl
                    $http.get(userInfoUrl).then(function (userResult) {
                        $rootScope.oauth2User = userResult.data;
                    }, function (error) {
                        console.log(error);
                    });
                }
            });
            $rootScope.$on('oauth2:authError', function () {
                if ($location.path().indexOf("/silent-renew") == 0 && $window.window.top && $window.window.parent && $window.window !== $window.window.top) {
                    // A 'child' frame failed to authorize.
                    $window.window.parent.postMessage("oauth2.silentRenewFailure", $location.protocol() + "//" + $location.host());
                }
                else {
                   handleUnauthorizedAccess();
                }
            });
            function handleUnauthorizedAccess(){
                 if (endpointSettings.unauthorizedAccessUrl && endpointSettings.unauthorizedAccessUrl.length > 0) {
                        $location.path(endpointSettings.unauthorizedAccessUrl);
                    }
                if(endpointSettings.unauthorizedAccessState && endpointSettings.unauthorizedAccessState.length>0){                        
                    $state.go(endpointSettings.unauthorizedAccessState);                        
                }
            }
            $rootScope.$on('oauth2:unauthorized', handleUnauthorizedAccess);
            $rootScope.$on('oauth2:authExpired', function () {
                $rootScope.signedIn = false;
                AccessToken.destroy();
            });
            $rootScope.signedIn = $rootScope.signedIn || AccessToken.set() !== null;
    }]);
})();
