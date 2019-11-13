package com.rgs.template.interceptor;

import com.alibaba.fastjson.JSON;
import com.rgs.core.annotation.Annoymous;
import com.rgs.core.annotation.Login;
import com.rgs.core.config.MdcConstant;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;


/**
 * 权限(Token)验证
 *
 * @author mz
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

        //Filter out all of non-business related request
        Boolean canSkip = false;
        if (request.getMethod().equals("OPTIONS")) {
            canSkip = true;
        }
        if(request.getRequestURI().indexOf("swagger")>=0){
            canSkip=true;
        }
        if (canSkip) {
            return true;
        }

        HashMap<String,Object> requestMap=new HashMap<>(8);

        String referer = request.getHeader("Referer");
        String requestUrl=request.getRequestURI();
        String uuid = UUID.randomUUID().toString().replaceAll("-", "");
        //Only get parameter, not request body
        Map<String,String[]> content=request.getParameterMap();
        String clientID="";

        requestMap.put("referer",referer);
        requestMap.put("requestUrl",requestUrl);
        requestMap.put("parameter",content);

        requestMap.put(MdcConstant.TRACE_ID,uuid);
        request.setAttribute(MdcConstant.TRACE_ID,uuid);
        MDC.put(MdcConstant.TRACE_ID,uuid);


        if (handler instanceof HandlerMethod) {

            if (((HandlerMethod) handler).hasMethodAnnotation(Login.class)) {
                canSkip = true;
            } else {
                if (((HandlerMethod) handler).hasMethodAnnotation(Annoymous.class)) {
                    canSkip = true;
                }
            }
        }
        //Skip all requests which has no need to make authentication validation
        if(canSkip){
            request.setAttribute(MdcConstant.TRACE_ID,uuid);
            MDC.put(MdcConstant.TRACE_ID,uuid);
            this.logInfo(requestMap);
            return true;
        }

        String token = request.getHeader("token");
        //TODO Get Client Info based on token
        clientID="Martin";
        MDC.put(MdcConstant.CLIENTID,clientID);
        requestMap.put(MdcConstant.CLIENTID,clientID);
        requestMap.put("token",token);


        this.logInfo(requestMap);
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

    private void logInfo(HashMap<String,Object> requestMap){

        try{
            String logJson=JSON.toJSONString(requestMap);
            log.info("[Request Info]{}",logJson);
        }catch(Exception ex){
            log.info("[Request Info error]{}:{}",ex.getMessage(),ex.getStackTrace());
        }

    }



}