
var rentalApp = angular.module("rentalApp", []);

rentalApp.config(function ($routeProvider) {
		$routeProvider.
			when('/', {
				controller: 'HomeController', 
				templateUrl: 'partials/home.html'
			}).
			when('/user-info', {
				controller: 'UserController', 
				templateUrl: 'partials/user-info.html'
			}).
			when('/login', { 
			    controller: 'LoginController', 
				templateUrl: 'partials/login.html'
			}).
			when('/registration', { 
			    controller: 'LoginController', 
				templateUrl: 'partials/registration.html'
			}).
			when('/invalid-server-response', { 
			    controller: 'UserController', 
				templateUrl: 'partials/invalid-server-response.html'
			}).
			when('/error', { 
			    controller: 'UserController', 
				templateUrl: 'partials/error.html'
			}).
			otherwise({ redirectTo: '/' });
	});
	
rentalApp.service ('authService', function($http, $rootScope, $location) {	
		var authInfo = { authenticated: false };
		
		this.getAuthInfo = function() {
			return authInfo;
		}
		
		this.refreshAuthInfo = function(redirect) {
			$http.get("user-info").
				success(function(data, status) {
					$rootScope.status = status;
					$rootScope.data = data;
					
					authInfo.authenticated = true;
					authInfo.accessToken = data.accessToken;
					authInfo.ticketNumber = data.ticketNumber;					
					authInfo.loggedUser = data.name;
					authInfo.associated = (data.accessToken != null);				
				}).
				error(function(data, status) {
					$rootScope.status = status;
					if (redirect == true && status == 401) {
						$location.path("/login");
					}
					else {
						$rootScope.data = data || "Request failed";
					}
					authInfo = { authenticated: false };	
				});
		};
		
		this.logout = function() {
			$http.post("auth/logout").
				success(function(data, status) {				
					authInfo = { authenticated: false };	
					$location.path("/");				
				}).
				error(function(data, status) {
					authInfo = { authenticated: false };	
					$location.path("/");
				});
		};
	});
	
rentalApp.controller('NavbarController', function ($scope, $location, authService) {	
	
	function pathUnder(suffix) {
 	   return $location.path().indexOf(suffix, $location.path().length - suffix.length) !== -1;
	}

	$scope.showNavigation = function() {
	    if (pathUnder("/login") || pathUnder("/registration"))
		    return false;
		else
			return true;
	}
	
	$scope.auth = function() {
		return authService.getAuthInfo();
	}

    $scope.getClass = function (path) {
        if (pathUnder(path)) {
            return true
        } else {
            return false;
        }
    }
    
    $scope.logout = function() {
    	authService.logout();    	
    	authService.refreshAuthInfo();
	}
});

rentalApp.controller('LoginController', function ($scope, $http, $location, $rootScope) {	
    $scope.register = function() {
    	 $http.post('register', { displayName: $scope.username, email: $scope.email, password: $scope.password }).
    	 	success(function(data, status) {
				$rootScope.status = status;
				$rootScope.data = data;
				
				$location.path("/");
			}).
			error(function(data, status) {
				$rootScope.data = data || "Request failed";
				$rootScope.status = status;
			});
	};
			
	$scope.signIn = function() {
    	 $http.post('auth/credentials?format=json', { UserName: $scope.username, Password: $scope.password }).
    	 	success(function(data, status) {
				$rootScope.status = status;
				$rootScope.data = data;

        		$location.path( "/" );    		
			}).
			error(function(data, status) {
				$rootScope.data = data || "Request failed";
				$rootScope.status = status;		
			});
	};
     
	$scope.go = function(path) {
	  $location.path(path);
	};
});

rentalApp.controller('HomeController', function ($scope, authService) {		
	// Ensure we always have up-to-date user information when coming here.
	// May not be necessary, though (we could move it to "login")
	authService.refreshAuthInfo();
	
	$scope.auth = function() {
		return authService.getAuthInfo();
	}
	
});

rentalApp.controller('UserController', function ($scope, $http, $location, $rootScope, authService) {	
	// Ensure we always have up-to-date user information when coming here.
	// May not be necessary, though (we could move it to "login")
	authService.refreshAuthInfo();
	
	$scope.auth = function() {
		return authService.getAuthInfo();
	}
		
	$scope.requestToken = function() {
		$http.post("sii-auth-request").
			success(function(data, status) {
				document.all = data;
				$scope.associated = true;
			}).
			error(function(data, status) {
			    $scope.associated = false;
				$scope.status = status;
				if (status == 401) {
					$location.path("/login");
				}
				else {
					$scope.data = data || "Request failed";
				}
			});
	};
});

