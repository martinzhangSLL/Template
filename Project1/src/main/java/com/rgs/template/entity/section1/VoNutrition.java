package com.rgs.template.entity.section1;

import lombok.Data;

import java.io.Serializable;

@Data
public class VoNutrition implements Serializable {

    private static final long serialVersionUID = 1L;

    private Integer servingSize;
    private String servingMeasurement=null;

    private Integer calories;
    private Integer fat;
    private Integer sodium;
    private Integer carbohydrate;
}
