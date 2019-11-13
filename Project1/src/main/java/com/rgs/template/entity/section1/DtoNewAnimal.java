package com.rgs.template.entity.section1;

import com.alibaba.fastjson.JSON;
import lombok.Data;

import java.io.Serializable;
import java.util.Date;

@Data
public class DtoNewAnimal implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * The name of animal
     */
    private String name;

    /**
     * The species of animal
     * e.g. Cat, Dog....
     */
    private String species;

    /**
     * The detailed species of animal
     * e.g. Chiwawa for dog
     */
    private String detailedSpecies;

    /**
     * The age of animal
     */
    private Integer age;


    /**
     * The date of birth of animal
     */
    private Date dateOfBirth;

    /**
     * 1: They have name
     * 2: They are noe required to create a new object
     *
     * @param animal
     * @return
     */
    public static synchronized DtoNewAnimal newInstance(DtoAnimal animal){

        if(animal==null){
            return null;
        }
        DtoNewAnimal dtoNewAnimal=new DtoNewAnimal();
        dtoNewAnimal.setName(animal.getAnimalName());
        dtoNewAnimal.setAge(animal.getAge());
        dtoNewAnimal.setDateOfBirth(animal.getDateOfBirth());
        dtoNewAnimal.setSpecies(animal.getSpecies());
        dtoNewAnimal.setDetailedSpecies("Unknown");
        return dtoNewAnimal;
    }

    /**
     * @return the summary properties of animal with the format of JSON
     */
    @Override
    public String toString(){

        return JSON.toJSONString(this);
    }

}
