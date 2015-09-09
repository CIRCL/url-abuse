(function () {
  'use strict';

  var app = angular.module('URLabuseApp', ['ui.bootstrap']);

  app.factory("flash", function($rootScope) {
    var queue = [];
    var currentMessage = "";

    $rootScope.$on("newFlashMessage", function() {
      currentMessage = queue.shift() || "";
    });

    return {
      setMessage: function(message) {
        queue.push(message);
      },
      getMessage: function() {
        return currentMessage;
      }
    };
  });

  app.factory('globFct', [ '$log', '$http', '$timeout', function($log, $http, $timeout){
      return {
          poller: function myself(jobID, callback) {
            var timeout = "";
            // fire another request
            $http.get('_result/' + jobID).
                success(function(data, status, headers, config) {
                    if(status === 202) {
                        $log.log(data, status);
                    } else if (status === 200){
                        $log.log(data);
                        $timeout.cancel(timeout);
                        callback(angular.fromJson(data));
                        return;
                    }
                    // continue to call the poller() function every 2 seconds
                    // until the timout is cancelled
                    timeout = $timeout(function() {myself(jobID, callback);}, 2000);
                });
          },
          query: function(path, data, callback) {
            $http.post(path, data).
                success(callback).
                error(function(error) {
                    $log.log(error);
                });
          }
      };
    }]);

  app.controller('URLabuseController', function($scope, $log, globFct, flash) {

    $scope.poller = globFct.poller;
    $scope.query = globFct.query;
    $scope.flash = flash;

    var get_redirects = function(jobID) {
        $scope.poller(jobID, function(data){
            $log.log(data);
            $scope.urls = data;
        });
    };


    $scope.getResults = function() {
      // get the URL from the input
      $scope.query_url = '';
      $scope.urls = '';
      // Reset the message
      $scope.$emit('newFlashMessage', '');

      var userInput = $scope.input_url;


      var check_validity = function(jobID) {
        $scope.poller(jobID, function(data){
            $scope.query_url = data[1];
            if(data[0] === false){
              $scope.error = data[2];
            } else {
                $scope.query('urls', {"url": data[1]}, get_redirects);
            }
        });
      };

      $scope.query('start', {"url": userInput}, check_validity);
    };

     $scope.submit_email = function() {
        $scope.query('submit', {"url":  $scope.query_url}, function(){
            $scope.query_url = '';
            $scope.urls = '';
            $scope.input_url = '';
            flash.setMessage("Mail sent to CIRCL");
            $scope.$emit('newFlashMessage', '');
        });
    };

  });

  app.directive('uqUrlreport', function(globFct) {

    return {
        scope: {
                  url: '=uqUrlreport',
                  // status: {isFirstOpen: true, isFirstDisabled: false}
          },
        link: function(scope, element, attrs) {
            var get_ips = function(jobID) {
                globFct.poller(jobID, function(data){
                    scope.ipv4 = data[0];
                    scope.ipv6 = data[1];
                    if (!scope.ipv4){
                        scope.ipv4 = ['Unable to resolve in IPv4'];
                    }
                    if (!scope.ipv6){
                        scope.ipv6 = ['Unable to resolve in IPv6'];
                    }
                });
            };
            globFct.query('resolve', {"url": scope.url}, get_ips);
        },
        templateUrl: 'urlreport',
    };

  });

  app.directive('uqPhishtank', function(globFct) {
      return {
          scope: {
                    query: '=data',
          },
          link: function(scope, element, attrs) {
              var get_response = function(jobID) {
                globFct.poller(jobID, function(data){
                    scope.response = data;
                });
              };
              globFct.query('phishtank', {"query": scope.query}, get_response);
          },
      template: function(elem, attr){
          return '<div ng-show="response" class="animate-show"><alert type="danger">Known phishing website on Phishtank. <a target="_blank" ng-href="{{response}}">More details</a>.</alert></div>';}
      };
  });

    app.directive('uqVirustotal', function(globFct) {
        return {
            scope: {
                      query: '=data',
            },
            link: function(scope, element, attrs) {
                var get_response = function(jobID) {
                  globFct.poller(jobID, function(data){
                      scope.message = data[0];
                      scope.link = data[1];
                      scope.positives = data[2];
                      scope.total = data[3];
                      if(scope.link && scope.positives === null){
                        scope.alert_val = "info";
                        scope.message = "Scan request successfully queued, report available soon.";
                      } else if (scope.link && scope.positives === 0){
                        scope.message = "None of the " + data[3] + " scanners know this URL as malicious.";
                        scope.alert_val = "success";
                      } else if (scope.link && scope.positives < scope.total/3){
                        scope.message = data[2] + " of the " + data[3] + " scanners know this URL as malicious.";
                        scope.alert_val = "warning";
                      } else if (scope.link && scope.positives >= scope.total/3){
                        scope.message = data[2] + " of the " + data[3] + " scanners know this URL as malicious.";
                        scope.alert_val = "danger";
                      }
                  });
                };
                globFct.query('virustotal_report', {"query": scope.query}, get_response);
            },
            template: function(elem, attr){
                return '<div ng-show="message" class="animate-show"><alert type="{{alert_val}}">{{message}} <a ng-if="link" target="_blank" ng-href="{{link}}">More details</a>.</alert></div>';}
        };
    });

    app.directive('uqGooglesafebrowsing', function(globFct) {
        return {
            scope: {
                      query: '=data',
            },
            link: function(scope, element, attrs) {
                var get_response = function(jobID) {
                  globFct.poller(jobID, function(data){
                      scope.response = data;
                  });
                };
                globFct.query('googlesafebrowsing', {"query": scope.query}, get_response);
            },
        template: function(elem, attr){
            return '<div ng-show="response" class="animate-show"><alert type="danger">Known {{response}} website on Google Safe Browsing. <a target="_blank" ng-href="https://www.google.com/safebrowsing/diagnostic?site={{query}}">More details</a>.</alert></div>';}
        };
    });

    app.directive('uqEupi', function(globFct) {
        return {
            scope: {
                      query: '=data',
            },
            link: function(scope, element, attrs) {
                var get_response = function(jobID) {
                  globFct.poller(jobID, function(data){
                      scope.response = data;
                      if(data === "clean"){
                        scope.alert_val = "success";
                      }
                      else{
                        ascope.alert_val = "danger";
                      }
                  });
                };
                globFct.query('eupi', {"query": scope.query}, get_response);
            },
        template: function(elem, attr){
            return '<div ng-show="response" class="animate-show"><alert type="{{alert_val}}">Known as {{response}} by the European Union antiphishing initiative.</alert></div>';}
        };
    });

    app.directive('uqUrlquery', function(globFct) {
        return {
            scope: {
                      query: '=data',
            },
            link: function(scope, element, attrs) {
                var get_response = function(jobID) {
                  globFct.poller(jobID, function(data){
                      scope.response = data;
                  });
                };
                globFct.query('urlquery', {"query": scope.query}, get_response);
            },
            template: function(elem, attr){
                return '<div ng-show="response" class="animate-show"><alert type="danger">The total alert count on URLquery is {{response}}.</alert></div>';}
            };
    });

    app.directive('uqTicket', function(globFct) {
        return {
            scope: {
                      query: '=data',
            },
            link: function(scope, element, attrs) {
                var get_response = function(jobID) {
                  globFct.poller(jobID, function(data){
                      scope.response = data;
                  });
                };
                globFct.query('ticket', {"query": scope.query}, get_response);
            },
        template: '<div ng-show="response.length > 0" class="animate-show">Tickets: <ul><div ng-repeat="ticket in response"><li><a target="_blank" ng-href={{ticket}}>{{ticket}}</a></li></div></ul></div>'
        };
    });

    app.directive('uqWhois', function(globFct) {
        return {
            scope: {
                      query: '=data',
            },
            link: function(scope, element, attrs) {
                var get_response = function(jobID) {
                  globFct.poller(jobID, function(data){
                      scope.response = data.join();
                  });
                };
                globFct.query('whois', {"query": scope.query}, get_response);
            },
        template: '<div ng-show="response" class="animate-show">Contact points from Whois: {{ response }}</div>'
        };
    });
    app.directive('uqPdnscircl', function(globFct) {
        return {
            scope: {
                      query: '=data',
            },
            link: function(scope, element, attrs) {
                var get_response = function(jobID) {
                  globFct.poller(jobID, function(data){
                      scope.nbentries = data[0];
                      scope.lastentries = data[1];
                  });
                };
                globFct.query('pdnscircl', {"query": scope.query}, get_response);
            },
        template: '<div ng-show="nbentries" class="animate-show">Has {{nbentries}} unique entries in CIRCL Passive DNS. {{lastentries.length}} most recent one(s): <ul><div ng-repeat="domain in lastentries"><li>{{domain}}</li></div></ul></div>'
        };
    });
    app.directive('uqPsslcircl', function(globFct) {
        return {
            scope: {
                      query: '=data',
            },
            link: function(scope, element, attrs) {
                var get_response = function(jobID) {
                  globFct.poller(jobID, function(data){
                      scope.entries = data;
                  });
                };
                globFct.query('psslcircl', {"query": scope.query}, get_response);
            },
            template: '<div ng-show="entries" class="animate-show">SSL certificates related to this IP: <ul><div ng-repeat="(sha1, subject) in entries"><li><b>{{sha1}}</b>: {{subject[0]}}</li></div></ul></div>'
        };
    });
    app.directive('uqBgpranking', function(globFct) {
        return {
            scope: {
                      query: '=data',
            },
            link: function(scope, element, attrs) {
                var get_response = function(jobID) {
                  globFct.poller(jobID, function(data){
                      scope.ptr = data[0];
                      scope.asndesc = data[1];
                      scope.asn = data[2];
                      scope.position = data[3];
                      scope.total = data[4];
                      scope.value = data[5];
                      if (scope.position < 100){
                          scope.alert_val = "danger";
                      } else if (scope.position < 1000){
                        scope.alert_val = "warning";
                      } else {
                          scope.alert_val = "info";
                      }
                  });
                };
                globFct.query('bgpranking', {"query": scope.query}, get_response);
            },
            template: '<div ng-show="asn" class="animate-show"><alert type="{{alert_val}}">Information from BGP Ranking: <ul><li ng-show="ptr">PTR Resource Record: {{ptr}}</li><li>Announced by: {{asndesc}} (<a target="_blank" ng-href="http://bgpranking.circl.lu/asn_details?asn={{asn}}">{{asn}}</a>)</li><li>This ASN is at position {{position}} in the list of {{total}} known ASNs ({{value}}).</li></ul></alert></div>'
        };
    });
}());
