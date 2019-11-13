package com.rgs.template.controller.Section1;

import com.rgs.core.exception.ServiceException;
import com.rgs.core.interaction.ServiceApiResult;
import com.rgs.template.entity.section1.DtoAnimal;
import com.rgs.template.entity.section1.DtoNewAnimal;
import com.rgs.template.interfaces.section1.Item1Service;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * Item 1: Consider static factory methods instead of constructors
 *
 * 1: 它们有名字
 * 2：不像构造函数，每次使用对象时都需要调用构造函数
 * 3：他可以实现适配的作用，即通过该方法实现相关对象之间的相互转换
 * 4：可是实现对象的基本检查，不用担心返回的对象因为属性不足而无法使用
 * 5：可以实现单例模式
 *
 * 不足：
 * 1：不推荐在bean中使用，因为java bean的生成必须要有空的构造函数，而一旦该方法用以生成单例，那么他就不会有无参构造函数
 * 2：不方便编程，不知道哪些类通过该方式生成对象
 *
 * 一般用来做关联的对象之间的转换或构造
 */
@RestController
@Api(tags="Creating and Destroying Objects", value="Section1")
@RequestMapping("section1")
public class Item1Controller {

    @Autowired
    Item1Service item1Service;


    @PostMapping("/item1")
    @ApiOperation(value = "item1")
    public ServiceApiResult<DtoNewAnimal> Getitem1(@RequestBody DtoAnimal model){

        ServiceApiResult result;
        try{

            DtoNewAnimal newAnimal=item1Service.getCorrectInstance(model);
            result=ServiceApiResult.ok(newAnimal);

        }
        catch(ServiceException ex){
            result=ServiceApiResult.error(ex.getMsg());
        }
        catch(Exception ex){
            result=ServiceApiResult.error(ex.getMessage());
        }
        return result;
    }
}
