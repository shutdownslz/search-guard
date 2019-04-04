package com.floragunn.searchguard.sgconf;


public class DynamicConfigFactory {
    
    //the returned classes are stable and can be filled by different config versions
    //config versions can have or support different features which older versions do not support 
    //make sure  we have implementations which can deal with thousands of roles, rolesmappings, internal users and tenants 
    
    public boolean hasDynamicConfig(DynamicConfigFeature feature) {
        return false;
    }
    
    //sg_action_groups.yml + static groups
    public ActionGroupModel getActionGroupModel() {
        return null;
    }
    
    //sg_roles.yml, sg_roles_mapping.yml, sg_tenants.yml + static roles
    public ConfigModel getConfigModel() { //to be renamed into RolesModel
        return null;
    }
    
    //sg_config.yml, sg_auditlog.yml
    public DynamicConfigModel getDynamicConfigModel() {
        return null;
    }

    //sg_internal_users.yml
    public InternalUsersModel getInternalUsersModel() {
        return null;
    }
}
