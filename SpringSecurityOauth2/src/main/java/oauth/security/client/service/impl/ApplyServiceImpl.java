package oauth.security.client.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import oauth.security.client.dao.ApplyDao;
import oauth.security.client.service.ApplyService;

import java.util.Map;

@Service
public class ApplyServiceImpl implements ApplyService{

    @Autowired
    private ApplyDao applyDao;

    @Override
    public Map findApplyById(String id) {
        return applyDao.findApplyById(id);
    }
}
