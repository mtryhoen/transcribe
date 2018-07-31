function awsCred(callback) {

    AWS.config.region = 'eu-west-1'; // Region
    var creds = AWS.config.credentials = new AWS.CognitoIdentityCredentials({
        IdentityPoolId: 'eu-west-1:5c811920-9ed9-4713-93b4-ce5ae70de196',
    });
    AWS.config.credentials.get(function(){

        // Credentials will be available when this function is called.
//        var accessKeyId = AWS.config.credentials.accessKeyId;
//        var secretAccessKey = AWS.config.credentials.secretAccessKey;
//        var sessionToken = AWS.config.credentials.sessionToken;
        var creds = {
           accessKeyId: AWS.config.credentials.accessKeyId,
           secretAccessKey: AWS.config.credentials.secretAccessKey,
           sessionToken: AWS.config.credentials.sessionToken
        }
        if (callback) {
            return callback(creds);
        }
    });

}