package com.rgs.core.annotation;

import java.lang.annotation.*;

/**
 * @author al
 * @date 2019/5/21 16:12
 * @description
 */
@Documented
@Inherited
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface FieldMapperToId {
    String dirId() default "";
}
