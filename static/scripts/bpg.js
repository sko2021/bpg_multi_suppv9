if ("undefined" == typeof jQuery) throw new Error("Missing jQuery");

function logout() {
    console.log("Initiating Logout");
    try {
        for (i = 0; i < logoutUrls.length; i++) {
        console.log("Calling URL[" + i + "]: " + logoutUrls[i]);
        $.ajax({
            url: logoutUrls[i],
            type: "GET",
			async: false,
        	cache: false,
        	timeout: 30000,
            success: function(data, status, jqXHR) {
                console.log("Status[" + i + "]: " +  jqXHR.status);
            },
            error: function(error) {
                console.log(error);
            }
        })
    }
}
catch(error){
    console.log(error);
}
	console.log("Redirecting to AAD Logout")
    location.href = 'logout';
}

function logout2(app_name) {
    console.log(`Initiating Logout For Application ${app_name}`);
    try {
        for (i = 0; i < logoutUrls.length; i++) {
        console.log("Calling URL[" + i + "]: " + logoutUrls[i]);
        // if (app_name==logoutUrls.)
        $.ajax({
            url: logoutUrls[i],
            type: "GET",
			async: false,
        	cache: false,
        	timeout: 30000,
            success: function(data, status, jqXHR) {
                console.log("Status[" + i + "]: " +  jqXHR.status);
            },
            error: function(error) {
                console.log(error);
            }
        })
    }
}
catch(error){
    console.log(error);
}}