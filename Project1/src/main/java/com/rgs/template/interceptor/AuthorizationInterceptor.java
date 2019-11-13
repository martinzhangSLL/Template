package com.rgs.template.interceptor;

import com.alibaba.fastjson.JSON;
import com.rgs.core.annotation.Annoymous;
import com.rgs.core.annotation.Login;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


/**
 * 权限(Token)验证
 *
 * @author chen
 * @email sunlightcs@gmail.com
 * @date 2017-03-23 15:38
 */
@Component
@Slf4j
public class AuthorizationInterceptor extends HandlerInterceptorAdapter {

    @Autowired
    private MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter;

    public static final String USER_KEY = "userInfo";

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String referer = request.getHeader("Referer");
        log.info("request的请求头。{}", referer);

        Boolean canSkip = false;
        if (handler instanceof HandlerMethod) {

            if (((HandlerMethod) handler).hasMethodAnnotation(Login.class)) {
                canSkip = true;
            } else {
                if (((HandlerMethod) handler).hasMethodAnnotation(Annoymous.class)) {
                    canSkip = true;
                }
            }
        }

        if (request.getMethod().equals("OPTIONS")) {
            canSkip = true;
        }
        if(request.getRequestURI().indexOf("swagger")>=0){
            canSkip=true;
        }
        if (canSkip) {
            return true;
        }

        String token = request.getHeader("token");
        log.info("[web校验]请求的TOKEN为：" + token);

        String uuid = UUID.randomUUID().toString().replaceAll("-", "");
        request.setAttribute("traceId",uuid);

        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With, token");
        response.setHeader("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS, POST, PUT, DELETE");
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Max-Age", "3600");
    }

}