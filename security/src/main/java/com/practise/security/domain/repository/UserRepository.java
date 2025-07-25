package com.practise.security.domain.repository;

import com.practise.security.domain.model.AuthUser;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<AuthUser, Long> {

  Optional<AuthUser> findByEmail(String username);
}
