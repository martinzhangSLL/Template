package com.rgs.core.util;

import java.util.regex.Pattern;

public class StringUtil {

    /**
     * 判断数字
     * @param str
     * @return
     */
    public static boolean isNumeric(String str){
        Pattern pattern = Pattern.compile("[0-9]*");
        return pattern.matcher(str).matches();
    }

    /**
     * 判断字母
     * @param str
     * @return
     */
    public static boolean isLetter(String str){
        Pattern pattern = Pattern.compile("[a-zA-Z]*");
        return pattern.matcher(str).matches();
    }

    /**
     * 判断车架号
     * @param str
     * @return
     */
    public static boolean isVinNumber(String str){
        Pattern pattern = Pattern.compile("(?=.*[0-9])(?=.*[a-zA-Z])[0-9a-zA-Z]{17}");
        return pattern.matcher(str).matches();
    }

    /**
     * 不为空返回true
     * @param str
     * @return
     */
    public static boolean isEmpty(String str){
        if(str==null || str.trim().length()==0){
            return true;
        }else{
            return false;
        }
    }

    /**
     * 判断设备号
     * @param str
     * @return
     */
    public static boolean isDeviceNumber(String str){
        Pattern pattern = Pattern.compile("^(\\d{15})$");
        return pattern.matcher(str).matches();
    }

    /**
     * 判断字符长度
     * @param str
     * @return
     */
    public static Integer constantStrLength(String str){
        if(str == null || str.trim().length() == 0 || str.length() > 40){
            return 0;
        }else{
            return 1;
        }
    }

    /**
     * 判断字符串是否是带小数点的数值
     * @param str
     * @return
     */
    public static boolean isNumericWithPoint(String str){
        Pattern pattern = Pattern.compile("0|([1-9]\\d*\\.?\\d*)|(0\\.\\d*[1-9])");
        return pattern.matcher(str).matches();
    }

    /**
     * 判断字符串是否是带负号
     * @param str
     * @return
     */
    public static boolean isMinusSign(String str){
        Pattern pattern = Pattern.compile("-0|-([1-9]\\d*\\.?\\d*)|-(0\\.\\d*[1-9])");
        return pattern.matcher(str).matches();
    }

    /**
     * 设备信息导入设备版本号格式校验
     * @param str
     * \d+ 匹配数字 (\.\d+) 匹配数字之后还有.数字 {0,2} 表示可以重复0-2次，匹配1.1和1.1.2的情况
     * @return
     */
    public static boolean isVersion(String str){
        Pattern pattern = Pattern.compile("\\d+(\\.\\d+){0,1}");
        return pattern.matcher(str).matches();
    }

}

