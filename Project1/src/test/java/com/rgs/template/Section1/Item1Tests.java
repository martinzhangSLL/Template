package com.rgs.template.Section1;

import com.rgs.core.exception.ServiceException;
import com.rgs.template.entity.section1.DtoAnimal;
import com.rgs.template.serviceimpl.section1.Item1ServieImpl;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.test.context.junit4.SpringRunner;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@RunWith(SpringRunner.class)
@ComponentScan("com.rgs.template")
public class Item1Tests {

    @InjectMocks
    private Item1ServieImpl item1Service;

    @Rule
    public ExpectedException thrown=ExpectedException.none();

    @Test(expected = ServiceException.class)
    public void invalidTest1 () throws ServiceException{

        DtoAnimal dtoAnimal=new DtoAnimal();
        dtoAnimal.setAnimalName(null);
        item1Service.getCorrectInstance(dtoAnimal);
    }

    @Test
    public void invalidTest2 () throws ServiceException{

        thrown.expect(ServiceException.class);
        thrown.expectMessage("Animal should not be null or empty");
        DtoAnimal dtoAnimal=null;
        item1Service.getCorrectInstance(dtoAnimal);
    }

    @Test
    public void invalidTest3 (){

        DtoAnimal dtoAnimal=new DtoAnimal();
        dtoAnimal.setAge(null);

        ServiceException exception=assertThrows(ServiceException.class,()->{
            item1Service.getCorrectInstance(dtoAnimal);
        });

        Assert.assertNotNull(exception);
    }
}
