//! AuthMethodManager tests

use ssh_client::auth::methods::*;
use ssh_client::protocol::AuthMethod;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_method_manager_new() {
        let manager = AuthMethodManager::new();
        assert_eq!(manager.usable_methods().len(), 0);
        assert!(manager.supported_methods.is_empty());
        assert!(manager.allowed_methods.is_empty());
    }

    #[test]
    fn test_auth_method_manager_default() {
        let manager: AuthMethodManager = Default::default();
        assert_eq!(manager.usable_methods().len(), 0);
    }

    #[test]
    fn test_auth_method_manager_add_supported() {
        let mut manager = AuthMethodManager::new();
        manager.add_supported(AuthMethod::Password);
        manager.add_supported(AuthMethod::PublicKey);
        
        assert_eq!(manager.supported_methods.len(), 2);
        assert!(manager.is_supported(AuthMethod::Password));
        assert!(manager.is_supported(AuthMethod::PublicKey));
        assert!(!manager.is_supported(AuthMethod::None));
    }

    #[test]
    fn test_auth_method_manager_add_supported_no_duplicates() {
        let mut manager = AuthMethodManager::new();
        manager.add_supported(AuthMethod::Password);
        manager.add_supported(AuthMethod::Password);
        manager.add_supported(AuthMethod::PublicKey);
        
        assert_eq!(manager.supported_methods.len(), 2);
    }

    #[test]
    fn test_auth_method_manager_add_allowed() {
        let mut manager = AuthMethodManager::new();
        manager.add_allowed(AuthMethod::Password);
        
        assert!(manager.is_allowed(AuthMethod::Password));
        assert!(!manager.is_allowed(AuthMethod::PublicKey));
    }

    #[test]
    fn test_auth_method_manager_add_allowed_no_duplicates() {
        let mut manager = AuthMethodManager::new();
        manager.add_allowed(AuthMethod::Password);
        manager.add_allowed(AuthMethod::Password);
        manager.add_allowed(AuthMethod::PublicKey);
        
        assert_eq!(manager.allowed_methods.len(), 2);
    }

    #[test]
    fn test_auth_method_manager_usable_methods_empty() {
        let mut manager = AuthMethodManager::new();
        manager.add_supported(AuthMethod::Password);
        // No allowed methods
        
        assert_eq!(manager.usable_methods().len(), 0);
    }

    #[test]
    fn test_auth_method_manager_usable_methods_intersection() {
        let mut manager = AuthMethodManager::new();
        manager.add_supported(AuthMethod::Password);
        manager.add_supported(AuthMethod::PublicKey);
        manager.add_allowed(AuthMethod::Password);
        manager.add_allowed(AuthMethod::None);
        
        let usable = manager.usable_methods();
        assert_eq!(usable.len(), 1);
        assert!(usable.contains(&AuthMethod::Password));
        assert!(!usable.contains(&AuthMethod::PublicKey));
        assert!(!usable.contains(&AuthMethod::None));
    }

    #[test]
    fn test_auth_method_manager_is_supported() {
        let mut manager = AuthMethodManager::new();
        manager.add_supported(AuthMethod::Password);
        
        assert!(manager.is_supported(AuthMethod::Password));
        assert!(!manager.is_supported(AuthMethod::PublicKey));
        assert!(!manager.is_supported(AuthMethod::None));
    }

    #[test]
    fn test_auth_method_manager_is_allowed() {
        let mut manager = AuthMethodManager::new();
        manager.add_allowed(AuthMethod::Password);
        
        assert!(manager.is_allowed(AuthMethod::Password));
        assert!(!manager.is_allowed(AuthMethod::PublicKey));
        assert!(!manager.is_allowed(AuthMethod::None));
    }

    #[test]
    fn test_auth_method_manager_all_methods() {
        let mut manager = AuthMethodManager::new();
        
        // Add all methods
        manager.add_supported(AuthMethod::Password);
        manager.add_supported(AuthMethod::PublicKey);
        manager.add_supported(AuthMethod::None);
        
        manager.add_allowed(AuthMethod::Password);
        manager.add_allowed(AuthMethod::PublicKey);
        
        assert_eq!(manager.supported_methods.len(), 3);
        assert_eq!(manager.allowed_methods.len(), 2);
        assert_eq!(manager.usable_methods().len(), 2);
        
        assert!(manager.is_supported(AuthMethod::Password));
        assert!(manager.is_supported(AuthMethod::PublicKey));
        assert!(manager.is_supported(AuthMethod::None));
        
        assert!(manager.is_allowed(AuthMethod::Password));
        assert!(manager.is_allowed(AuthMethod::PublicKey));
        assert!(!manager.is_allowed(AuthMethod::None));
    }
}