package com.rgs.core.annotation;

import java.lang.annotation.*;

/**
 * @author al
 * @date 2019/5/20 10:52
 * @description
 */
@Documented
@Inherited
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface FieldMapperDesc {

    String dirValue() default "";
    String descName() default "";

}
