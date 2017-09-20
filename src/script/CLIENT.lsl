// LSL: Update/CLIENT
// shinate


// ================================
// = The following 4 must be set  =
// ================================
string PRODUCTION_NAME      = "";
string PRODUCTION_VERSION   = "";
string PROROCOL_SINGNATURE  = ""; // your own signature
float  PROTOCOL_VERSION     = 0.0; // can range from 0.0 to 255.255
string SECRET_STRING        = "";


// ================================
integer SECRET_NUMBER = 0;
string PRODUCTION_NAME_ENCRYPT;

//Chibiusa lings shiz
string Header;
string strHex = "0123456789ABCDEF";

string SERVER_MAPPING_SYNC_SERVICE_URL = "http://sl0sync0update0server.duapp.com/api/production/get";
key HTTP_REQUEST_ID;

integer DEBUG = 0;

Debug(string message)
{
    if( DEBUG == 1 )
    {
        llOwnerSay(message);
    }
}

string hex(integer value)
{
    integer digit = value & 0xF;
    string text = llGetSubString(strHex, digit, digit);
    value = (value >> 4) & 0xfffFFFF;
    integer odd = TRUE;
    while(value)
    {
        digit = value & 0xF;
        text = llGetSubString(strHex, digit, digit) + text;
        odd = !odd;
        value = value >> 4;
    }
    if(odd)
        text = "0" + text;
    return text;
}

string encrypt(string password, string message)
{
    // get a random value
    integer nonce = (integer)llFrand(0x7FFFFFFF);
 
    // generate digest and prepend it to message
    message = llMD5String(message, nonce) + message;
 
    // generate one time pad
    string oneTimePad = llMD5String(password, nonce);
 
    // append pad until length matches or exceeds message
    integer count = (llStringLength(message) - 1) / 32;
    if(count)
        do
            oneTimePad += llMD5String(oneTimePad, nonce);
        while(--count);
 
    // return the header, nonce and encrypted message
    return Header + llGetSubString("00000000" + hex(nonce), -8, -1) + llXorBase64StringsCorrect(llStringToBase64(message), llStringToBase64(oneTimePad));
}

init()
{
    //build the header, it never changes.
    list versions = llParseString2List((string)PROTOCOL_VERSION, ["."], []);
    string minor = llList2String(versions, 1);
    integer p = 0;
    while(llGetSubString(minor, --p, p) == "0");
    Header = PROROCOL_SINGNATURE + hex(llList2Integer(versions, 0)) + hex((integer)llGetSubString(minor, 0xFF000000, p));    
}

// send post request
key post(string url, list params)
{
    integer i;
    string body;
    integer len = llGetListLength(params) & 0xFFFE; // make it even
    for (i = 0; i < len; i += 2)
    {
        string varname = llList2String(params, i);
        string varvalue = llList2String(params, i + 1);
        if (i > 0)
        {
            body += "&";
        }
        body += llEscapeURL(varname) + "=" + llEscapeURL(varvalue);
    }
    string hash = llMD5String(body + llEscapeURL(SECRET_STRING), SECRET_NUMBER);
    return llHTTPRequest(url + "?hash=" + hash, [
            HTTP_METHOD, "POST",
            HTTP_MIMETYPE, "application/x-www-form-urlencoded"
        ], body);
}

default
{
    state_entry() {
        llSetText("", <0,0,0>, 0.0);
        if( PRODUCTION_NAME == "" || PROROCOL_SINGNATURE == "" || SECRET_STRING == "" )
        {
            llSetText("NO SETTINGS", <1,0,0>, 1.0);
            state Error;
        }
        init();
        PRODUCTION_NAME_ENCRYPT = llMD5String(PRODUCTION_NAME, SECRET_NUMBER);
    }

    touch_start(integer num_detected)
    {
        if( llGetOwner() == llDetectedKey(0) )
        {
            llOwnerSay("Checking for update ...");
            HTTP_REQUEST_ID = post(SERVER_MAPPING_SYNC_SERVICE_URL, [
                "production", PRODUCTION_NAME_ENCRYPT
                ]);
        }
    }

    attach(key id)
    {
        if( llGetOwner() == id )
        {
            llOwnerSay("Checking for update ...");
            HTTP_REQUEST_ID = post(SERVER_MAPPING_SYNC_SERVICE_URL, [
                "production", PRODUCTION_NAME_ENCRYPT
                ]);
        }
    }

    http_response(key request_id, integer status, list metadata, string body)
    {

        Debug(llDumpList2String([request_id, status, body], ", "));

        if(request_id == HTTP_REQUEST_ID)
        {
            HTTP_REQUEST_ID = NULL_KEY;

            if(status == 200)
            {
                integer code = (integer)llJsonGetValue(body, ["code"]);
                string message = llJsonGetValue(body, ["msg"]);
                if(code == 0)
                {
                    if(message == "SERVER_URL")
                    {
                        string server_url = llJsonGetValue(body, ["data", "server_url"]);
                        HTTP_REQUEST_ID = post(server_url, [
                            "q", encrypt(SECRET_STRING, llList2Json(JSON_OBJECT, [
                                "user", llGetOwner(),
                                "username", llGetUsername(llGetOwner()),
                                "production", PRODUCTION_NAME_ENCRYPT,
                                "version", PRODUCTION_VERSION,
                                "request", "UPDATE" 
                                ]))
                            ]);
                    }
                    else if(message == "WAITTING_FOR_UPDATES")
                    {
                        llOwnerSay("The latest version of the product has been sent, please click Agree to receive. Thank you for choosing our products :3");
                    }
                }
                else
                {
                    llOwnerSay(message);
                }
            }
            else
            {
                llOwnerSay("The update server is temporarily offline，please try again later.");
            }
        }
        llSetText("", <1,1,1>, 0.0);
    }
}

state Error
{
    state_entry()
    {
        return;
    }

    changed(integer change)
    {
        if(change == CHANGED_INVENTORY)
        {
            llResetScript();
        }   
    }

}