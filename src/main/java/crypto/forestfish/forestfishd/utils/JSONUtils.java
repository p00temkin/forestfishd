package crypto.forestfish.forestfishd.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.alibaba.fastjson.JSON;

import crypto.forestfish.forestfishd.api.v1.ForestFishV1Request_authenticate;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Request_knockknock;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Response_authenticate;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Response_challenge;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Response_knockknock;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Response_protectedcontent;
import crypto.forestfish.forestfishd.api.v1.ForestFishV1Response_status;

public class JSONUtils {

	private static final Logger LOGGER = LoggerFactory.getLogger(JSONUtils.class);
	
	public static String createJSONFromV1ForestFishStatusResponse(ForestFishV1Response_status data) {
		String jsonString = "";
		try {
			jsonString = JSON.toJSONString(data);
		} catch (Exception e) {
			LOGGER.error("Exception during JSON parsing: " + e.getClass() + ": " + e.getMessage(), e);
		}
		return jsonString;
	}
	
	public static String createJSONFromV1ForestFishKnockKnockResponse(ForestFishV1Response_knockknock data) {
		String jsonString = "";
		try {
			jsonString = JSON.toJSONString(data);
		} catch (Exception e) {
			LOGGER.error("Exception during JSON parsing: " + e.getClass() + ": " + e.getMessage(), e);
		}
		return jsonString;
	}
	
	public static String createJSONFromV1ForestFishChallengeResponse(ForestFishV1Response_challenge data) {
		String jsonString = "";
		try {
			jsonString = JSON.toJSONString(data);
		} catch (Exception e) {
			LOGGER.error("Exception during JSON parsing: " + e.getClass() + ": " + e.getMessage(), e);
		}
		return jsonString;
	}
	
	public static String createJSONFromV1ForestFishProtectedContent(ForestFishV1Response_protectedcontent data) {
		String jsonString = "";
		try {
			jsonString = JSON.toJSONString(data);
		} catch (Exception e) {
			LOGGER.error("Exception during JSON parsing: " + e.getClass() + ": " + e.getMessage(), e);
		}
		return jsonString;
	}
	
	public static String createJSONFromV1ForestFishAuthenticateResponse(ForestFishV1Response_authenticate data) {
		String jsonString = "";
		try {
			jsonString = JSON.toJSONString(data);
		} catch (Exception e) {
			LOGGER.error("Exception during JSON parsing: " + e.getClass() + ": " + e.getMessage(), e);
		}
		return jsonString;
	}
	
	public static String createJSONFromV1ForestFishAuthenticateRequest(ForestFishV1Request_authenticate data) {
		String jsonString = "";
		try {
			jsonString = JSON.toJSONString(data);
		} catch (Exception e) {
			LOGGER.error("Exception during JSON parsing: " + e.getClass() + ": " + e.getMessage(), e);
		}
		return jsonString;
	}
	
    public static ForestFishV1Response_challenge createForestFishV1Response_challenge(String json) {
    	ForestFishV1Response_challenge ev = null;
        try {
            ev = JSON.parseObject(json, ForestFishV1Response_challenge.class);
        } catch (Exception e) {
            LOGGER.error("Exception during JSON parsing: " + e.getClass() + ": " + e.getMessage(), e);
            LOGGER.error("JSON string for above error: " + json);
        }
        return ev;
    }
    
	
    public static ForestFishV1Response_authenticate createForestFishV1Response_authenticate(String json) {
    	ForestFishV1Response_authenticate ev = null;
        try {
            ev = JSON.parseObject(json, ForestFishV1Response_authenticate.class);
        } catch (Exception e) {
            LOGGER.error("Exception during JSON parsing: " + e.getClass() + ": " + e.getMessage(), e);
            LOGGER.error("JSON string for above error: " + json);
        }
        return ev;
    }
    
    public static ForestFishV1Request_authenticate createForestFishV1Request_authenticate(String json) {
    	ForestFishV1Request_authenticate ev = null;
        try {
            ev = JSON.parseObject(json, ForestFishV1Request_authenticate.class);
        } catch (Exception e) {
            LOGGER.error("Exception during JSON parsing: " + e.getClass() + ": " + e.getMessage(), e);
            LOGGER.error("JSON string for above error: " + json);
        }
        return ev;
    }
    
    public static ForestFishV1Request_knockknock createForestFishV1Request_knockknock(String json) {
    	ForestFishV1Request_knockknock ev = null;
        try {
            ev = JSON.parseObject(json, ForestFishV1Request_knockknock.class);
        } catch (Exception e) {
            LOGGER.error("Exception during JSON parsing: " + e.getClass() + ": " + e.getMessage(), e);
            LOGGER.error("JSON string for above error: " + json);
        }
        return ev;
    }
	
    
}
