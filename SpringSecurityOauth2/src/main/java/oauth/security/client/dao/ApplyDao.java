package oauth.security.client.dao;

import org.apache.ibatis.annotations.Mapper;

import java.util.Map;

@Mapper
public interface ApplyDao {

    Map findApplyById(String id);

}
