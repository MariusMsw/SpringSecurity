package com.example.SpringSecurity.dao;

import com.example.SpringSecurity.models.User;
import org.springframework.stereotype.Repository;

import java.util.Optional;

public interface UserDao { 

    Optional<User> selectUserByUsername(String username);
}
