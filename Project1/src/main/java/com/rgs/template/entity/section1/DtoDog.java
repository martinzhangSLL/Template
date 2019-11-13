package com.rgs.template.entity.section1;

import lombok.Data;
import java.io.Serializable;

/**
 * The entity object of dog
 */
@Data
public class DtoDog extends DtoAnimal implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * The gender of animal
     */
    private String gender;

}
