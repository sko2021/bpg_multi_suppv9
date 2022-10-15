require([ "dijit/registry", "dojo/parser", "dojo/ready", "dojo/query", "dojo/dom-class", "dojo/NodeList-dom" ], 
		function(registry, parser, ready, query, domClass) {
	// Show the dialog
	showBSAAssignments = function() {
		registry.byId("bsaAssignments").show();
		return false;
	};
	
	ready(function() {
		return false;
	});
});

jQuery(function($) {
    if($(window).width()>769){
        $('.navbar .dropdown').hover(function() {
            $(this).find('.dropdown-menu').first().stop(true, true).delay(250).slideDown();

        }, function() {
            $(this).find('.dropdown-menu').first().stop(true, true).delay(100).slideUp();

        });

        $('.navbar .dropdown > a').click(function(){
            location.href = this.href;
        });

    }
});




// support for nav tabs active item 

$(function () {
    setNavigation();
});

function setNavigation() {
    var path = window.location.pathname;
    path = path.replace(/\/$/, "");
    path = decodeURIComponent(path);

    $(".nav-tabs a").each(function () {
        var href = $(this).attr('href');
        if (path.substring(0, href.length) === href) {
            $(this).closest('li').addClass('active');
        }
    });
}

function switchVisible() {
    if (document.getElementById('Div1')) {

        if (document.getElementById('Div1').style.display == 'none') {
            document.getElementById('Div1').style.display = 'block';
            document.getElementById('Div2').style.display = 'none';
        }
        else {
            document.getElementById('Div1').style.display = 'none';
            document.getElementById('Div2').style.display = 'block';
        }
    }
}

