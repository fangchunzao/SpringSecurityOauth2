package com.oauth.client.rest;

import com.oauth.client.domain.User;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author FCZ
 * @since 2018/9/29 17:25
 */
@RequestMapping("/Test")
@RestController
public class TestRest {

    @RequestMapping({ "/user", "/me" })
    public Map<String, String> user(@RequestBody User user) {
        Map<String, String> map = new LinkedHashMap<>();
        map.put("name", user.getName());
        return map;
    }


}
