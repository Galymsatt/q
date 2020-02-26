package com.project.demo.repositories;

import com.project.demo.entities.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<Users, Long> {

    Users findByEmailAndIsActiveIsTrue(String email);
//    Users findByEmailAndIsActiveIsTrue(String email);
//    Users findByEmailAndIsActiveIsTrue(String email);
    Optional<Users> findById(Long id);

}
