package com.ssafy.server.global.response;

import java.util.HashMap;
import java.util.Map;

public class Response {
    public static Map success(Map<String, Object> map) {
        Map<String, Object> result = new HashMap<>();
        result.put("resultCode", "Success");
        result.put("data", map);

        return result;
    }

    public static Map fail(Map<String, String> map) {
        Map<String, Object> result = new HashMap<>();
        result.put("resultCode", "Fail");
        result.put("data", map);

        return result;
    }
}
