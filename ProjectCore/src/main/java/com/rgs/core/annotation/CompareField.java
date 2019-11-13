package com.rgs.core.annotation;

import java.lang.annotation.*;

/**
 * @author al
 * @date 2019/4/24 10:03
 * @description
 */
@Documented
@Inherited
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface CompareField {

    String[] value() default {};

    boolean justRemindChange() default false;
}
