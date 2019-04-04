/*
 * Copyright 2015-2017 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.configuration;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.floragunn.searchguard.sgconf.impl.CType;
import com.floragunn.searchguard.sgconf.impl.SgDynamicConfiguration;
import com.floragunn.searchguard.sgconf.impl.v6.ActionGroups;

public class ActionGroupHolder {

    final ConfigurationRepository configurationRepository;

    public ActionGroupHolder(final ConfigurationRepository configurationRepository) {
        this.configurationRepository = configurationRepository;
    }

    private Set<String> getGroupMembers(final String groupname) {

        SgDynamicConfiguration<?> actionGroups = (SgDynamicConfiguration<ActionGroups>) configurationRepository.getConfiguration(CType.ACTIONGROUPS);

        if (actionGroups == null) {
            return Collections.emptySet();
        }

        return Collections.unmodifiableSet(resolve(actionGroups, groupname));
    }

    private Set<String> resolve(final SgDynamicConfiguration<?> actionGroups, final String entry) {

        
        // SG5 format, plain array
        //List<String> en = actionGroups.getAsList(DotPath.of(entry));
        //if (en.isEmpty()) {
        	// try SG6 format including readonly and permissions key
        // 	en = actionGroups.getAsList(DotPath.of(entry + "." + ConfigConstants.CONFIGKEY_ACTION_GROUPS_PERMISSIONS));
        	//}
        
        if(!actionGroups.getCEntries().containsKey(entry)) {
            return Collections.emptySet();
        }
        
        final Set<String> ret = new HashSet<String>();
        
        final Object actionGroupAsObject = actionGroups.getCEntries().get(entry);
        
        if(actionGroupAsObject != null && actionGroupAsObject instanceof List) {
            
            for (final String perm: ((List<String>) actionGroupAsObject)) {
                if (actionGroups.getCEntries().keySet().contains(perm)) {
                    ret.addAll(resolve(actionGroups,perm));
                } else {
                    ret.add(perm);
                }
            }
            
            
        } else if(actionGroupAsObject != null &&  actionGroupAsObject instanceof ActionGroups) {
            for (final String perm: ((ActionGroups) actionGroupAsObject).getPermissions()) {
                if (actionGroups.getCEntries().keySet().contains(perm)) {
                    ret.addAll(resolve(actionGroups,perm));
                } else {
                    ret.add(perm);
                }
            }
        } else {
            throw new RuntimeException("Unable to handle "+actionGroupAsObject);
        }
        
        return Collections.unmodifiableSet(ret);
    }
    
    public Set<String> resolvedActions(final List<String> actions) {
        final Set<String> resolvedActions = new HashSet<String>();
        for (String string: actions) {
            final Set<String> groups = getGroupMembers(string);
            if (groups.isEmpty()) {
                resolvedActions.add(string);
            } else {
                resolvedActions.addAll(groups);
            }
        }

        return Collections.unmodifiableSet(resolvedActions);
    }
}
