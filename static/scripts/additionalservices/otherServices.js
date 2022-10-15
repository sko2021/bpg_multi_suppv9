require(
		[ "dijit/registry", "dojo/parser", "dojo/ready", "dojo/query",
				"dojo/dom-class", "dojo/has", "dojo/_base/sniff", "dojo/dom-style", "dijit/Tooltip", "dojo/_base/array", "dojo/NodeList-dom"  ],
		function(registry, parser, ready, query, domClass, has, style, Tooltip, array) {

			var clickedOnce = new Boolean(null);
			
			// *********************************************************************************
			ready(function() {
				return false;
			});

			// *********************************************************************************
			/*
			 * show and hide descriptions for services
			 */
			showHideDesc = function(id, ctx){
				var approvedNum = id;
				var descNum = "desc"+id;
				var dropText = "more"+id;
				var origin = window.location.protocol + "//" + window.location.host + ctx;
				if(document.getElementById(approvedNum).alt == "image of plus symbol"){
					document.getElementById(approvedNum).src = origin+"/images/gui/bkg/icons/minus-grey.png";
					document.getElementById(approvedNum).alt = "image of minus symbol";
					document.getElementById(descNum).style.display = "block";
					document.getElementById(dropText).alt = "less"+id;
					document.getElementById(dropText).title = "Click to minimize";
					document.getElementById(dropText).innerHTML = "less info >";
				}else{
					document.getElementById(approvedNum).src = origin+"/images/gui/bkg/icons/plus-grey.png";
					document.getElementById(approvedNum).alt = "image of plus symbol";
					document.getElementById(descNum).style.display = "none";
					document.getElementById(dropText).alt = "more"+id;
					document.getElementById(dropText).title = "Click to learn more"
					document.getElementById(dropText).innerHTML = "more info >";
				}
			};
			
			/**************************************
			 * request access new version
			 */
			submitRequest = function(serviceID, command) {
				dojo.byId('serviceId').value = serviceID;
				dojo.xhrPost({
					url : "/eAdmin/action/addservice/checkPopup",
					form : "selectServicesForm",
					handleAs: "json",
					load : function(response) {
						if(response) {
							showDialog(serviceID, command);
						}else{
							yesClickHandler("ADMIN");
						}
					},
					error : function(error) {
						dojo.byId("response").innerHTML = "Form posted.";
					}
				});
			};
			
			/******************************************************
			 * show BSA dialog Yes/No button event function
			 */
			yesClickHandler = function(value) {
				hideBSADialog();
				dojo.byId("roleName").value = value;
				dojo.xhrPost({
					url: "/eAdmin/action/addservice/requestAccess",
					form: "selectServicesForm",
					handleAs: "text",
					load: function(response) {
						var node = dojo.byId("servicesTableId");
						var widgets = dijit.findWidgets(node);
						// Before update
						if (widgets) {
							dojo.forEach(widgets, function(widget, i) {
								widget.destroyRecursive(false);
							});									   
						} 
						dojo.empty(node);
						node.innerHTML = response;
						parser.parse(node);
					},
					error: function(error) {
					}
				});
				return false;
			};
			

			// *********************************************************************************
			showDialog = function(serviceID, command) {
				query("html, body").addClass("no-scroll");
				registry.byId("become_bsa_popup").show();
				var regId = registry.byId("become_bsa_popup");
				regId.connect(regId, "hide", function() {
					query("html, body").removeClass("no-scroll");					
				});
				dojo.byId('serviceId').value = serviceID;
				command = "modelButton";
				return false;
			};

			// Hide the dialog
			hideBSADialog = function() {
				registry.byId("become_bsa_popup").hide();
				return false;
			};


		});