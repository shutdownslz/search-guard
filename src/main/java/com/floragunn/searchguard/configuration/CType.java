package com.floragunn.searchguard.configuration;

public enum CType {
    
    INTERNAL_USERS(InternalUsers.class),
    ACTION_GROUPS(ActionGroups.class),
    CONFIG(Config.class),
    ROLES(Role.class),
    ROLE_MAPPINGS(RoleMappings.class);
    
    private Class implementationClazz;

    private CType(Class implementationClazz) {
        this.implementationClazz = implementationClazz;
    }

    public Class getImplementationClass() {
        return implementationClazz;
    }
}
