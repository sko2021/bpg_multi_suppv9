require(
		[ "dijit/registry", "dojo/ready", "dojo/query" ],
		function(registry, ready, query) {
			// Milliseconds before user will be logged out
			var interval = 840000; //14 minutes
			var oneMinHold = 60000; // 1 minute
//			var interval = 60000; // 1 min
//			var oneMinHold = 30000; // 30 sec
			var timeout;

			// *********************************************************************************

			ready(function() {
				timeoutInit();
//				dojo.connect(dojo.byId("pageBodyId"), "onclick", function(evt) {
//					window.clearTimeout(timeout);
//					timeoutInit();
//				});

				//popup modal dialog: OK button is clicked
				dojo.connect(dojo.byId("TimeOutCloseButtonId"), "onclick", function(evt) {
					hideTimeOutDialog();		
				});
				
				return false;
			});

			/********************
			 * Hide the dialog
			 * 
			 */
			hideTimeOutDialog = function() {
				registry.byId("timeOutDialogId").hide();
				window.clearTimeout(timeout);
				resetCntr();
				timeoutInit();
				return false;
			};

			// *********************************************************************************

			// show the dialog
			showTimeOutDialog = function() {
				window.clearTimeout(timeout);
				timeout = window.setTimeout(redirectLogout, oneMinHold);
				registry.byId("timeOutDialogId").show();

				return false;
			};

			// *********************************************************************************

			timeoutInit = function() {
				timeout = window.setTimeout(showTimeOutDialog, interval);
			};

			// *********************************************************************************

			redirectLogout = function() {
				window.location.href = "/eAdmin/view/signin/logout";
			};

			// *********************************************************************************
			resetCntr = function() {
				dojo.xhrGet({
					url : "/eAdmin/action/homepage/reset",
					handleAs : 'json',
					load : function() {
					}
				});
			};
			// *********************************************************************************

			displayBusyButton = function(buttonId) {
				if (buttonId) {
					dojo.empty(buttonId);
					dojo.byId(buttonId).innerHTML = dojo.byId("processingButtonDiv").innerHTML;
				}
			};
		});