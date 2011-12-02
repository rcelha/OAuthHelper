/**
 * http://oauth.googlecode.com/svn/code/javascript/
 * 
 * This a helper to authenticate using oauth
 */

var OAuthHelper = {};

OAuthHelper.utils = {
    urlParameters: function(value){
        var r = {};
        value = value.split('?');
        value = value.length > 1? value[1] : value[0];
        
        value.split('&').forEach(function(v){
            if(v == "") return;
            var tmp = v.split('=');
            if(tmp.length != 2) return;
            r[tmp[0]] = tmp[1];
        });
        return r;
    },
    
    /**
     * TODO: implementation this method wo jQuery
     */
    request: function(url, method, params){
        r = $.ajax({
            url: url,
            type: method,
            async: false,
            data: params
        });
        return r.responseText;
    },
    
    jsonRequest: function(url, method, params, callback){
        r = $.ajax({
            url: url,
            type: method,
            dataType: 'json',
            async: true,
            success: callback,
            fail: callback,
            data: params
        });
    }
};

OAuthHelper.OAuth = (function(config){
    /**
     * config 
     *  {
     *      id: 'myId' (needed to cache the keys)
     *      urls: {request_token, authorize, access_token },
     *      consumer_key
     *      consumer_secret
     *      oauth_token_secret
     *      oauth_token
     *      from_session
     *  }
     */
    this.constructor = function(config){
        for(var k in config){
            this[k] = config[k]
        }
        
        this.signature_method = "HMAC-SHA1";
        
        if(this.from_session){
            this.load_from_session();
        }
    };
    
    this.getAccessor = function(){
        return {
            consumerSecret: this.consumer_secret,
            tokenSecret: this.oauth_token_secret ? this.oauth_token_secret : ""
        };
    };

    /**
     * @param   url
     * @param   config (options: method, parameters)
     */
    this.getMessage = function(url, config){
        var config = config ? config : {};
        var method = config.method ? config.method : 'GET';
        var parameters = config.parameters ? config.parameters : {};
        
        parameters.oauth_consumer_key = this.consumer_key;
        parameters.oauth_signature_method = this.signature_method;
        
        if(this.oauth_token) parameters.oauth_token = this.oauth_token;
        
        return { 
            action: url,
            method: method,
            parameters: parameters
        };
    };

    /**
     * @see this.getMessage
     */
    this.getRequestData = function(url, config){
        var accessor = this.getAccessor();
        var message = this.getMessage(url, config);
        OAuth.completeRequest(message, accessor);
        return {
            accessor: accessor,
            message: message
        };
    },
    
    this.setSessionItem = function(name, value){
        return sessionStorage.setItem([this.id, name].join('__'), value);
    };

    this.getSessionItem = function(name, value){
        return sessionStorage.getItem([this.id, name].join('__'));
    };

    this.load_from_session = function(){
        
        oauth_token = this.getSessionItem('oauth_token');
        oauth_token_secret = this.getSessionItem('oauth_token_secret');
        auth_complete = this.getSessionItem('auth_complete');
        
        if(!auth_complete){
            return false;
        }else{
            this.oauth_token = oauth_token;
            this.oauth_token_secret = oauth_token_secret;
            return true;
        }
    },
    
    /**
     * below, the 3 steps of authentication
     */
    this.doRequestToken = function(){
        var requestData = this.getRequestData(this.urls.request_token, {});
        var m = requestData.message;
        var response = OAuthHelper.utils.request(m.action, m.method, m.parameters);
        
        response = OAuthHelper.utils.urlParameters(response);
        
        /**
         * sess stuff
         */
        this.setSessionItem('oauth_token', response.oauth_token);
        this.setSessionItem('oauth_token_secret', response.oauth_token_secret);
        this.oauth_token = response.oauth_token;
        
        return response;
    };
    
    this.doAuthorize = function(){
        var requestData = this.getRequestData(this.urls.authorize, {
            parameters: {
                oauth_callback: window.location.href + '?action=access_token'
            }
        });
        var m = requestData.message;
        var params = [];
        for(k in m.parameters){
            params.push(k + "=" + m.parameters[k]);
        }
        params = params.join('&');
        var url = m.action + '?' + params;
        
        window.location.href = url;
    },
    
    this.doAccessToken = function(){
        if(this.load_from_session()) return;
    
        this.oauth_token = this.getSessionItem('oauth_token');
        this.oauth_token_secret = this.getSessionItem('oauth_token_secret');
    
        var requestData = this.getRequestData(this.urls.access_token, {method: 'POST'});
        var m = requestData.message;
        var response = OAuthHelper.utils.request(m.action, m.method, m.parameters);
        
        response = OAuthHelper.utils.urlParameters(response);

        /**
         * sess stuff
         */
        this.setSessionItem('oauth_token', response.oauth_token);
        this.setSessionItem('oauth_token_secret', response.oauth_token_secret);
        this.setSessionItem('auth_complete', true);
        
        this.oauth_token = response.oauth_token;
        this.oauth_token_secret = response.oauth_token_secret;
    },

    this.constructor.call(this, config);
});