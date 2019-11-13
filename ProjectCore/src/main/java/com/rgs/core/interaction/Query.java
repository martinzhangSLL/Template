package com.rgs.core.interaction;

import com.baomidou.mybatisplus.mapper.BaseMapper;
import com.baomidou.mybatisplus.mapper.EntityWrapper;
import com.baomidou.mybatisplus.plugins.Page;
import com.rgs.core.util.StringUtil;
import com.rgs.core.xss.SQLFilter;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 查询参数
 *
 * @author Mark sunlightcs@gmail.com
 * @since 2.0.0 2017-03-14
 */
public class Query<T> extends LinkedHashMap<String, Object> {
    private static final long serialVersionUID = 1L;
    /**
     * mybatis-plus分页参数
     */
    private Page<T> page;
    /**
     * 当前页码
     */
    private int currPage = 1;
    /**
     * 每页条数
     */
    private int limit = 10;

    private EntityWrapper<T> entityWrapper;

    private BaseMapper baseMapper;

    public Query(Map<String, Object> params) {
        this.putAll(params);

        // 分页参数
        if (params.get("pageindex") != null) {
            currPage = Integer.parseInt(String.valueOf(params.get("pageindex")));
        }
        if (params.get("pagesize") != null) {
            limit = Integer.parseInt(String.valueOf(params.get("pagesize")));
        }

        this.put("offset", (currPage - 1) * limit);
        this.put("page", currPage);
        this.put("limit", limit);

        // 防止SQL注入（因为sidx、order是通过拼接SQL实现排序的，会有SQL注入风险）
        // String sidx = SQLFilter.sqlInject((String)params.get("sidx"));
        // String order = SQLFilter.sqlInject((String)params.get("order"));
        // this.put("sidx", sidx);
        // this.put("order", order);

        // mybatis-plus分页
        this.page = new Page<>(currPage, limit);

        // 排序
        // if(StringUtils.isNotBlank(sidx) && StringUtils.isNotBlank(order)){
        // this.page.setOrderByField(sidx);
        // this.page.setAsc("ASC".equalsIgnoreCase(order));
        // }

    }

    public Query(BaseMapper baseMapper, PagingOptions pagingOptions) {
        this.baseMapper = baseMapper;
        // 分页参数
        this.page = new Page<>(pagingOptions.getPageIndex(), pagingOptions.getPageSize());

        // Build Query
        this.entityWrapper = new EntityWrapper<T>();

        // Build Filter
        if (pagingOptions.getFilters() != null) {
            for (PagingFilter filter : pagingOptions.getFilters()) {

                if (StringUtil.isEmpty(filter.getField()) || StringUtil.isEmpty(filter.getOp())) {
                    continue;
                }

                String strOp = filter.getOp().trim();

                // 解决sql可能被注入的问题
                String term = "";
                String field = "";
                try {
                    field = filter.getField().trim();
                    field = SQLFilter.sqlInject(field);
                    term = SQLFilter.sqlInject(filter.getTerm());
                } catch (Exception ex) {
                    continue;
                }
                switch (strOp) {
                case "eq":
                    this.entityWrapper.eq(field, term);
                    break;
                case "ne":
                    this.entityWrapper.ne(field, term);
                    break;
                case "lt":
                    this.entityWrapper.lt(field, term);
                    break;
                case "le":
                    this.entityWrapper.le(field, term);
                    break;
                case "gt":
                    this.entityWrapper.gt(field, term);
                    break;
                case "ge":
                    this.entityWrapper.ge(field, term);
                    break;
                case "cn":
                    this.entityWrapper.like(field, term);
                    break;
                case "nu":
                    this.entityWrapper.isNull(field);
                    break;
                case "nn":
                    this.entityWrapper.isNotNull(field);
                    break;
                case "in":
                    List<String> result = Arrays.asList(term.split(","));
                    this.entityWrapper.in(field, result);
                    break;
                }

            }
        }

        if (pagingOptions.getSorts() != null) {
            // Build Order
            for (PagingSort sort : pagingOptions.getSorts()) {

                if (StringUtil.isEmpty(sort.getField()) || StringUtil.isEmpty(sort.getSort())) {
                    continue;
                }

                String strOp = sort.getSort().trim();
                switch (strOp) {
                case "asc":
                    this.entityWrapper.orderBy(sort.getField());
                    break;
                case "desc":
                    this.entityWrapper.orderBy(sort.getField(), false);
                    break;
                }
            }
        }
    }

    public Page<T> getPage() {
        return page;
    }

    public int getCurrPage() {
        return currPage;
    }

    public int getLimit() {
        return limit;
    }

    public EntityWrapper<T> getQueryWrapper() {
        return this.entityWrapper;
    }

    public WebApiResult buildResult() {

        try {

            page.setRecords(baseMapper.selectPage(page, entityWrapper));
            page.setTotal(baseMapper.selectCount(entityWrapper));
            PageUtils<T> pageUtil = new PageUtils<>(page);
            return WebApiResult.ok().put("data", pageUtil.getList()).put("count", pageUtil.getTotalCount());

        } catch (Exception ex) {

            return WebApiResult.error(ex.getMessage());
        }
    }
}
