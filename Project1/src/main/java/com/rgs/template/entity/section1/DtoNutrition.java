package com.rgs.template.entity.section1;

import com.rgs.core.exception.ServiceException;
import com.rgs.core.util.StringUtil;
import lombok.AccessLevel;
import lombok.Data;
import lombok.Setter;

import java.io.Serializable;

/**
 * The entity of nutrtion
 *
 * @author mz
 * @date 2019-11-07
 */
@Data
@Setter(AccessLevel.PRIVATE)
public class DtoNutrition implements Serializable {

    private static final long serialVersionUID = 1L;

    private Integer servingSize=null;
    private String servingMeasurement=null;
    private Integer calories=null;
    private Integer fat=null;
    private Integer sodium=null;
    private Integer carbohydrate=null;

    /**
     * The builder special for building the entity of DtoNutrtion
     */
    public static class Builder {

        // Required parameters
        private Integer servingSize = null;
        private String servingMeasurement=null;

        // Optional parameters - initialized to default values
        private Integer calories = null;
        private Integer fat = null;
        private Integer sodium = null;
        private Integer carbohydrate = null;

        //Only for mandatory field
        public Builder(Integer servingSize, String servingMeasurement) {

            if(servingSize==null || servingSize<=0){
                throw new ServiceException("Serving size should more than 0");
            }
            if(StringUtil.isEmpty(servingMeasurement)){
                throw new ServiceException("Serving should have measurement");
            }
            this.servingSize = servingSize;
            this.servingMeasurement=servingMeasurement;
        }
        public Builder calories(Integer val)
        { calories = val; return this; }

        public Builder fat(Integer val)
        { fat = val; return this; }

        public Builder sodium(Integer val)
        { sodium = val; return this; }
        public Builder carbohydrate(Integer val)
        { carbohydrate = val; return this; }

        public DtoNutrition build() {
            return new DtoNutrition(this);
        }
    }

    private DtoNutrition(Builder builder) {

        servingSize = builder.servingSize;
        servingMeasurement=builder.servingMeasurement;
        calories = builder.calories;
        fat = builder.fat;
        sodium = builder.sodium;
        carbohydrate = builder.carbohydrate;
    }
}
