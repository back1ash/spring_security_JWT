package com.example.springJWT.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.springJWT.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    Boolean existsByUsername(String username);
}