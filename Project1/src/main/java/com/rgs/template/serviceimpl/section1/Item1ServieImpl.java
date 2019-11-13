package com.rgs.template.serviceimpl.section1;

import com.rgs.core.exception.ServiceException;
import com.rgs.core.util.StringUtil;
import com.rgs.template.entity.section1.DtoAnimal;
import com.rgs.template.entity.section1.DtoNewAnimal;
import com.rgs.template.interfaces.section1.Item1Service;
import org.springframework.stereotype.Service;

/**
 * The interfaces implementation of item1
 *
 * @author mz
 * @date 2019-11-06
 */
@Service
public class Item1ServieImpl implements Item1Service {

    /**
     * Get correct instance by using the item1
     *
     * @return the dto of new animal object
     */
    @Override
    public DtoNewAnimal getCorrectInstance(DtoAnimal animal) {

        try{

            //Check the validation of animal
            this.checkAnimal(animal);

            //Create a new object of newAnimal
            DtoNewAnimal dtoNewAnimal=DtoNewAnimal.newInstance(animal);
            return dtoNewAnimal;
        }
        catch(ServiceException ex){
            throw ex;
        }
        catch(Exception ex){
            throw new ServiceException(ex.getMessage(),ex);
        }
    }

    /**
     * Check the validation of animal object system passed in
     * @param animal
     */
    private void checkAnimal(DtoAnimal animal){

        if(animal==null){
            throw new ServiceException("Animal should not be null or empty");
        }
        if(StringUtil.isEmpty(animal.getAnimalName())){
            throw new ServiceException("Animal should have name");
        }
        if(StringUtil.isEmpty(animal.getSpecies())){
            throw new ServiceException("Animal should have its own species");
        }
        if(animal.getAge()==null){
            throw new ServiceException("Animal should have age");
        }
        if(animal.getAge()<0){
            throw new ServiceException("Animal should have age over zero");
        }
    }
}
