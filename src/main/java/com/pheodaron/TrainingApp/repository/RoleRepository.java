package com.pheodaron.TrainingApp.repository;

import com.pheodaron.TrainingApp.enums.ERole;
import com.pheodaron.TrainingApp.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);

    Optional<Role> findByName(ERole name);
}
