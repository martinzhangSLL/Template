package com.rgs.core.interaction;

import com.alibaba.fastjson.JSON;
import com.rgs.core.util.AESUtil;

import java.util.HashMap;
import java.util.Map;

/**
 * 返回数据
 * 
 * @author chenshun
 * @email sunlightcs@gmail.com
 * @date 2016年10月27日 下午9:59:27
 */
public class WebApiResult extends HashMap<String, Object> {
	private static final long serialVersionUID = 1L;
	
	public WebApiResult() {
		put("code", 0);
		put("state",true);
		put("msg", "success");
	}
	
	public static WebApiResult error() {
		return error(500, "未知异常，请联系管理员");
	}
	
	public static WebApiResult error(String msg) {
		return error(500, msg);
	}
	
	public static WebApiResult error(int code, String msg) {
		WebApiResult r = new WebApiResult();
		r.put("code", code);
		r.put("state",false);
		r.put("msg", msg);
		return r;
	}

	public static WebApiResult ok(String msg) {
		WebApiResult r = new WebApiResult();
		r.put("msg", msg);
		return r;
	}
	public static WebApiResult ok(String msg,String appid) {
		WebApiResult r = new WebApiResult();
		r.put("msg", msg);
		r.put("appid", appid);
		return r;
	}
	
	public static WebApiResult ok(Map<String, Object> map) {
		WebApiResult r = new WebApiResult();
		r.putAll(map);
		return r;
	}
	
	public static WebApiResult ok() {
		return new WebApiResult();
	}

	@Override
	public WebApiResult put(String key, Object value) {
		super.put(key, value);
		return this;
	}

	public WebApiResult put(String key, Object value, Boolean isAES) {
		if(isAES){
			AESUtil aesUtil = new AESUtil();
			String strLoanEntity = JSON.toJSONString(value);
			value = AESUtil.encrypt(strLoanEntity);
		}

		super.put(key, value);
		return this;
	}
	
	public static WebApiResult toMap(String key, Object value) {
		WebApiResult r = new WebApiResult();
//		r.clear();
		r.put(key, value);
		return r;
		
	}

	public static WebApiResult toMap(String key, Object value, Boolean isAES) {
		WebApiResult r = new WebApiResult();
//		r.clear();
		r.put(key, value, isAES);
		return r;

	}
}
