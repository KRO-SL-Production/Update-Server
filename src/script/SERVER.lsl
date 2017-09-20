// LSL: Update/SERVER
// shinate

string CONFIG_FILE = "_CONFIG";
string CONFIG; // json

integer CONTROL_CHANNEL = -3400;

string PRODUCTION_NAME;
string PRODUCTION_SENDING_NAME;
string PRODUCTION_VERSION;
string PROROCOL_SINGNATURE; // your own signature
float PROTOCOL_VERSION; // can range from 0.0 to 255.255
string SECRET_STRING;
string ALERTS_EMAIL;

integer SECRET_NUMBER = 0;
string PRODUCTION_NAME_ENCRYPT;
string SERVER_URL;

key SELF_CHECK_REQUEST_ID;
key HTTP_REQUEST_SYNC_ID;
string SERVER_MAPPING_SYNC_SERVICE_URL = "http://sl0sync0update0server.duapp.com/api/production/publish";
key HTTP_REQUEST_PING_ID;
string PING_SYNC_SERVICE_URL = "http://sl0sync0update0server.duapp.com/api/production/ping";
key HTTP_REQUEST_RECORD_SENT_ID;
string RECORD_SENT_URL = "http://sl0sync0update0server.duapp.com/api/production/record_sent";

integer INVALID_RETRY;
integer INVALID_MAX = 5;

key notecard_query_id;
integer notecard_line;

list TEXT_DISP_LIST;

integer SENT_NUM = 0;

// Colors
vector NAVY    = <0,     0.122, 0.247>;
vector BLUE    = <0,     0.455, 0.851>;
vector AQUA    = <0.498, 0.859, 1    >;
vector TEAL    = <0.224, 0.8,   0.8  >;
vector OLIVE   = <0.239, 0.6,   0.439>;
vector GREEN   = <0.18,  0.8,   0.251>;
vector LIME    = <0.004, 1    , 0.439>;
vector YELLOW  = <1    , 0.863, 0    >;
vector ORANGE  = <1    , 0.522, 0.106>;
vector RED     = <1    , 0.255, 0.212>;
vector MAROON  = <0.522, 0.078, 0.294>;
vector FUCHSIA = <0.941, 0.071, 0.745>;
vector PURPLE  = <0.694, 0.051, 0.788>;
vector WHITE   = <1    , 1    , 1    >;
vector SILVER  = <0.867, 0.867, 0.867>;
vector GRAY    = <0.667, 0.667, 0.667>;
vector BLACK   = <0.000, 0.000, 0.000>;

// TIMER
integer BOOT_TIME;
integer _T;

integer SENSOR_PING_SYNC_SERVER = -1;
integer SENSOR_PING_SYNC_SERVER_T = 0;

integer DIALOG_CHANNEL;
integer DIALOG_HANDLE;

string TMP_SENT_MESSAGE;

integer DEBUG = 0;

Debug(string message)
{
    if( DEBUG == 1 )
    {
        llOwnerSay(message);
    }
}

request_url()
{
    llReleaseURL(SERVER_URL);
    SERVER_URL = "";
    SELF_CHECK_REQUEST_ID = llRequestURL();
}

set_link_text(integer linknum, string text, vector color, float alpha)
{
    llSetLinkPrimitiveParamsFast(llList2Integer(TEXT_DISP_LIST, linknum), [PRIM_TEXT, text, color, alpha]);
}

string decrypt(string password, string message)
{
    integer signatureLength = llStringLength(PROROCOL_SINGNATURE);
    integer headerLength = signatureLength + 12; // version = 4, nonce = 8
 
    // verify length of encrypted message
    if(llStringLength(message) < signatureLength + 44) // digest = 32 (base64 = 44) + at least one character
        return "Too small for secret message.";
 
    // look for protocol signature in message header
    if(llSubStringIndex(message, PROROCOL_SINGNATURE) != 0)
        return "Unknown protocol.";
 
    // Parse version information from header
    integer index = signatureLength; // determine where to start parsing
    string major = "0x" + llGetSubString(message, index, ++index);
    string minor = "0x" + llGetSubString(message, ++index, ++index);
    float version = (float)((string)((integer)major) + "." + (string)((integer)minor));
 
    // verify version is supported
    if(version != PROTOCOL_VERSION)
        return "Unknown version.";
 
    // parse nonce from header
    integer nonce = (integer)("0x" + llGetSubString(message, ++index, index + 7));
 
    // remove header from message
    message = llGetSubString(message, headerLength, -1);
 
    // create one time pad from password and nonce
    string oneTimePad = llMD5String(password, nonce);
    // append pad until length matches or exceeds message
    while(llStringLength(oneTimePad) < (llStringLength(message) / 2 * 3))
        oneTimePad += llMD5String(oneTimePad, nonce);
 
    // decrypt message
    oneTimePad = llStringToBase64(oneTimePad);
    message = llXorBase64StringsCorrect(message, oneTimePad);
 
    // decode message
    message = llBase64ToString(message);
 
    // get digest
    string digest = llGetSubString(message, 0, 31);
 
    // remove digest from message
    message = llGetSubString(message, 32, -1);
 
    // verify digest is valid
    if(llMD5String(message, nonce) != digest)
        return "Message digest was not valid.";
 
    // return decrypted message
    return message;
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

string get_post_value(string content, string returns)
{
//  this parses application/x-www-form-urlencoded POST data
 
//  for instance if the webserver posts 'data1=hi&data2=blah' then
//  calling get_post_value("data1=hi&data2=blah","data1"); would return "hi"
//  written by MichaelRyan Allen, Unrevoked Clarity
 
    list params =  llParseString2List(content,["&"],[]);
    integer index = ~llGetListLength(params);
 
    list keys;// = [];
    list values;// = [];
 
    // start with -length and end with -1
    while (++index)
    {
        list parsedParams =  llParseString2List(llList2String(params, index), ["="], []);
        keys += llUnescapeURL(llList2String(parsedParams, 0));
        values += llUnescapeURL(llList2String(parsedParams, 1));
    }
 
    integer found = llListFindList(keys, [returns]);
    if(~found)
        return llList2String(values, found);
//  else
        return "";
}

send_item(key to)
{
    Debug("Item <" + PRODUCTION_SENDING_NAME + "> has been sent.");
    llGiveInventory(to, PRODUCTION_SENDING_NAME);
}

string wwGetSLUrl()
{
    string globe = "http://maps.secondlife.com/secondlife";
    string region = llGetRegionName();
    vector pos = llGetPos();
    string posx = (string)llRound(pos.x);
    string posy = (string)llRound(pos.y);
    string posz = (string)llRound(pos.z);
    return (globe + "/" + llEscapeURL(region) +"/" + posx + "/" + posy + "/" + posz);
}

open_menu(key inputKey, string inputString, list inputList)
{
    DIALOG_CHANNEL = (integer)llFrand(DEBUG_CHANNEL) * -1;
    DIALOG_HANDLE = llListen(DIALOG_CHANNEL, "", inputKey, "");
    llDialog(inputKey, inputString, inputList, DIALOG_CHANNEL);
    llSetTimerEvent(30.0);
}

close_menu()
{
    llSetTimerEvent(0.0);
    llListenRemove(DIALOG_HANDLE);
}

default
{
    state_entry() {

        llResetTime();

        BOOT_TIME = llGetUnixTime();

        TEXT_DISP_LIST = [
            "TEXT_DISP_0",
            "TEXT_DISP_1",
            "TEXT_DISP_2",
            "TEXT_DISP_3",
            "TEXT_DISP_4"
        ];

        Debug("TEXT_DISP_LIST: " + llDumpList2String(TEXT_DISP_LIST, ","));

        integer i = 0;
        integer len = llGetNumberOfPrims();
        integer prim_index;
        string linked_prim_name;

        while ( i <= len )
        {
            linked_prim_name = llGetLinkName(i);

            prim_index = llListFindList(TEXT_DISP_LIST, [linked_prim_name]);

            if( ~prim_index )
            {
                TEXT_DISP_LIST = llListReplaceList((TEXT_DISP_LIST = []) + TEXT_DISP_LIST, [i], prim_index, prim_index);
                set_link_text(prim_index, "", BLACK, 0.0);
            }

            i++;
        }

        llSetText("", BLACK, 0.0);

        Debug("TEXT_DISP_LIST: " + llDumpList2String(TEXT_DISP_LIST, ","));

        state init;
    }
}

state init
{
    state_entry()
    {
        set_link_text(0, "Loading configurations ...", SILVER, 1.0);

        integer type = llGetInventoryType(CONFIG_FILE);

        if( type == INVENTORY_NOTECARD )
        {
            notecard_line = 0;
            notecard_query_id = llGetNotecardLine(CONFIG_FILE, notecard_line);
        }
        else
        {
            set_link_text(0, "The configuration file could not be found!", RED, 1.0);
            state Error;
        }
    }

    dataserver(key query_id, string data)
    {
        if (query_id == notecard_query_id)
        {
            if (data == EOF)
            {
                Debug("CONFIG: " + CONFIG);

                if(CONFIG == "")
                {
                    set_link_text(0, "Can not find any configuration!", RED, 1.0);
                    state Error;
                }
                else
                {
                    PRODUCTION_NAME = llJsonGetValue(CONFIG, ["PRODUCTION_NAME"]);
                    PRODUCTION_SENDING_NAME = llJsonGetValue(CONFIG, ["PRODUCTION_SENDING_NAME"]);
                    PRODUCTION_VERSION = llJsonGetValue(CONFIG, ["PRODUCTION_VERSION"]);
                    PROROCOL_SINGNATURE = llJsonGetValue(CONFIG, ["PROROCOL_SINGNATURE"]);
                    string protocol_version_string = llJsonGetValue(CONFIG, ["PROTOCOL_VERSION"]);
                    SECRET_STRING = llJsonGetValue(CONFIG, ["SECRET_STRING"]);
                    ALERTS_EMAIL = llJsonGetValue(CONFIG, ["ALERTS_EMAIL"]);

                    if( PRODUCTION_NAME == JSON_INVALID 
                        || PRODUCTION_SENDING_NAME == JSON_INVALID 
                        || PRODUCTION_VERSION == JSON_INVALID 
                        || PROROCOL_SINGNATURE == JSON_INVALID 
                        || protocol_version_string == JSON_INVALID 
                        || SECRET_STRING == JSON_INVALID )
                    {
                        set_link_text(0, "Required configuration is missing!", RED, 1.0);
                        state Error;
                    }

                    PROTOCOL_VERSION = (float)protocol_version_string;

                    state Main;
                }
            }
            else
            {
                data = llStringTrim(data, STRING_TRIM);
                Debug("Line " + (string) notecard_line + ": " + data);
                if (data != "" && llGetSubString(data, 0, 0) != "#") // ignore empty lines, or lines beginning with "#"
                {
                    integer index = llSubStringIndex(data, " ");
                    string k;
                    string v;
                    if(-1 < index)
                    {
                        k = llGetSubString(data, 0, index - 1);
                        v = llStringTrim(llDeleteSubString(data, 0, index - 1), STRING_TRIM_HEAD);
                        CONFIG = llJsonSetValue(CONFIG, [k], v);
                    }
                }
                ++notecard_line;
                notecard_query_id = llGetNotecardLine(CONFIG_FILE, notecard_line);
            }
        }
    }
}

state Main
{

    state_entry() {

        PRODUCTION_NAME_ENCRYPT = llMD5String(PRODUCTION_NAME, SECRET_NUMBER);
        Debug("PRODUCTION_NAME_ENCRYPT: " + PRODUCTION_NAME_ENCRYPT);

        set_link_text(4, "<Production Name>\n" + (string)PRODUCTION_NAME, LIME, 1.0);
        set_link_text(3, "<Sending Name>\n" + (string)PRODUCTION_SENDING_NAME + " [Version: " + (string)PRODUCTION_VERSION + "]", AQUA, 1.0);

        Debug("START TIME SENSOR");
        llSetTimerEvent(1.0);

        request_url();
    }

    on_rez(integer start_param)
    {
        llResetScript();
    }
 
    changed(integer change)
    {
        if (change & (CHANGED_OWNER | CHANGED_INVENTORY))
        {
            llReleaseURL(SERVER_URL);
            SERVER_URL = "";

            llResetScript();
        }
 
        if (change & (CHANGED_REGION | CHANGED_REGION_START | CHANGED_TELEPORT))
        {
            request_url();
        }
    }

    http_request(key id, string method, string body) {

        if (id == SELF_CHECK_REQUEST_ID)
        {
            SELF_CHECK_REQUEST_ID = NULL_KEY;

            SERVER_URL = body;
            // submit body to cloud
            Debug("Now, this object request URL: " + SERVER_URL);

            set_link_text(0, "Publish to sync server ...", GREEN, 1.0);

            HTTP_REQUEST_SYNC_ID = post(SERVER_MAPPING_SYNC_SERVICE_URL, [
                "user", llGetOwner(),
                "password", SECRET_STRING,
                "production", PRODUCTION_NAME_ENCRYPT,
                "production_name", PRODUCTION_NAME,
                "version", PRODUCTION_VERSION,
                "server_url", SERVER_URL
            ]);
        }
        else
        {
            if (method == "POST")
            {
                string encryptedString = get_post_value(body, "q");

                if(encryptedString)
                {
                    string params = decrypt(SECRET_STRING, encryptedString);
                    string user = llJsonGetValue(params, ["user"]);
                    string username = llJsonGetValue(params, ["username"]);
                    string production = llJsonGetValue(params, ["production"]);
                    string version = llJsonGetValue(params, ["version"]);
                    string request = llJsonGetValue(params, ["request"]);

                    if(production == PRODUCTION_NAME_ENCRYPT && request == "UPDATE")
                    {

                        if(llGetInventoryType(PRODUCTION_SENDING_NAME) != INVENTORY_NONE)
                        {
                            Debug("Send to: " + username + "," + user + "," + PRODUCTION_VERSION);
                            llHTTPResponse(id, 200, llList2Json(JSON_OBJECT, [
                                "code", 0,
                                "msg", "WAITTING_FOR_UPDATES"
                            ]));

                            send_item(user);

                            SENT_NUM++;

                            TMP_SENT_MESSAGE = "<" + username + "> requested an update (" + version + ")\n<" + PRODUCTION_SENDING_NAME + "> (" + PRODUCTION_VERSION + ") has been sent";

                            set_link_text(2, TMP_SENT_MESSAGE, FUCHSIA, 1.0);
                            
                            HTTP_REQUEST_RECORD_SENT_ID = post(RECORD_SENT_URL, [
                                "production", PRODUCTION_NAME_ENCRYPT,
                                "user", user,
                                "user_name", username,
                                "user_version", version,
                                "sent_version", PRODUCTION_VERSION
                            ]);
                        }
                        else
                        {
                            Debug("No items to send");
                            llHTTPResponse(id, 200, llList2Json(JSON_OBJECT, [
                                "code", 1,
                                "msg", "The update server is busy，please try again later."
                                ]));
                        }
                    }
                }
            }
        }
    }

    http_response(key request_id, integer status, list metadata, string body)
    {
        Debug("REQUEST_ID: " + llDumpList2String([request_id], ","));
        Debug("STATUS: " + llDumpList2String([status], ","));
        Debug("META: " + llDumpList2String(metadata, ","));
        Debug("BODY: " + llDumpList2String([body], ","));

        if(request_id == HTTP_REQUEST_SYNC_ID)
        {
            if(status == 200)
            {
                string code = llJsonGetValue(body, ["code"]);
                string message = llJsonGetValue(body, ["msg"]);
                Debug((string)code + " : " + message);
                if(code == "0")
                {
                    integer sent = (integer)llJsonGetValue(body, ["data", "sent"]);
                    SENT_NUM = sent;
                    set_link_text(0, message, GREEN, 1.0);
                    SENSOR_PING_SYNC_SERVER = 5;
                }
                else
                {
                    set_link_text(0, message, RED, 1.0);
                }

                return;
            }

            set_link_text(0, "Sync failed! The sync server is invalid!", RED, 1.0);
        }
        else if(request_id == HTTP_REQUEST_PING_ID)
        {
            if(status == 200)
            {
                string code = llJsonGetValue(body, ["code"]);
                if(code == "0")
                {
                    set_link_text(0, "RUNNING <" + (string)llFloor(llGetTime() / 3600) + "> HOURS\n~ The sync server is in service ~", GREEN, 1.0);
                    SENSOR_PING_SYNC_SERVER = 1800;
                    if(INVALID_RETRY >= INVALID_MAX)
                    {
                        if(ALERTS_EMAIL != JSON_INVALID && ALERTS_EMAIL != "")
                        {
                            llEmail(
                                ALERTS_EMAIL,
                                "The sync server is BACK~ Message from " + PRODUCTION_NAME,
                                "HAVE FUN"
                                );
                        }
                    }
                    INVALID_RETRY = 0;
                    return;
                }
            }

            if(INVALID_RETRY < INVALID_MAX)
            {
                llInstantMessage(llGetOwner(), "The sync server is invalid! Message from " + PRODUCTION_NAME);
                SENSOR_PING_SYNC_SERVER = 300;
                INVALID_RETRY++;
            }
            else
            {
                if(ALERTS_EMAIL != JSON_INVALID && ALERTS_EMAIL != "")
                {
                    llEmail(
                        ALERTS_EMAIL,
                        "The sync server is invalid! Message from " + PRODUCTION_NAME,
                        "TELEPORT TO SERVER: " + wwGetSLUrl()
                        );
                }
                SENSOR_PING_SYNC_SERVER = 3600;
            }
        }
        else if(request_id == HTTP_REQUEST_RECORD_SENT_ID)
        {
            if(status == 200)
            {
                string code = llJsonGetValue(body, ["code"]);
                string msg = llJsonGetValue(body, ["msg"]);
                if(code == "0")
                {
                    set_link_text(2, TMP_SENT_MESSAGE + "\n< ~ RECORDED ~ >", FUCHSIA, 1.0);
                }

                return;
            }
        }
    }

    timer()
    {
        _T = llGetUnixTime();

        if( ~SENSOR_PING_SYNC_SERVER )
        {
            if( SENSOR_PING_SYNC_SERVER_T == 0)
            {
                SENSOR_PING_SYNC_SERVER_T = _T;
            }

            if( _T - SENSOR_PING_SYNC_SERVER_T >= SENSOR_PING_SYNC_SERVER )
            {
                set_link_text(0, "Detects the sync server ...", YELLOW, 1.0);
                HTTP_REQUEST_PING_ID = llHTTPRequest(PING_SYNC_SERVICE_URL + "?t=" + (string)llGetUnixTime(), [], "");
                SENSOR_PING_SYNC_SERVER = -1;
                SENSOR_PING_SYNC_SERVER_T = 0;
            }
        }

        set_link_text(1, "" +
            "[TIME: " + (string)(_T - BOOT_TIME) + "] " + 
            "[MEM: " + (string)llGetUsedMemory() + "/" + (string)llGetMemoryLimit() + "] " + 
            "[SENT: " + (string)SENT_NUM + "]", ORANGE, 1.0);
    }
}

state Error
{
    state_entry()
    {

    }

    changed(integer change)
    {
        if(change == CHANGED_INVENTORY)
        {
            llResetScript();
        }   
    }

    touch_start(integer num_detected)
    {
        if( llGetOwner() == llDetectedKey(0) )
        {
            open_menu(llGetOwner(), "What you want to do", ["ReConnect", "ReStart"]);
        }
    }

    listen(integer channel, string name, key id, string message)
    {
        Debug((string)channel + " " + name + " " + (string)id + " " + message);

        if( llGetOwnerKey(id) == llGetOwner() )
        {
            if( channel == DIALOG_CHANNEL )
            {
                close_menu();

                if( message == "ReConnect" )
                {
                    INVALID_RETRY = 0;
                    state Main;
                }
                else if( message == "ReStart" )
                {
                    llResetScript();
                }
            }
        }
    }

    timer()
    {
        close_menu();
    }
}