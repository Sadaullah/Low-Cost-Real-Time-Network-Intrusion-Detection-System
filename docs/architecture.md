# Network Architecture

## Project
NetGuard Pi – Low-Cost Real-Time Network Intrusion Detection System

## Purpose
This document describes the network architecture used for the Raspberry Pi-based Intrusion Detection System.

## Components

- Raspberry Pi 4 – IDS Sensor
- Suricata – Intrusion Detection Engine
- Kali Linux – Test/Attacker Machine
- Victim PC – Windows or Linux
- Router
- Managed Switch
- Internet Connection

## Proposed Architecture

Internet
|
Router
|
Managed Switch
|--- Victim PC
|--- Raspberry Pi IDS Sensor
|--- Kali Linux Test Machine

## Monitoring Method

The Raspberry Pi will receive network traffic through switch port mirroring.

Suricata will inspect the mirrored traffic and generate alerts when suspicious activity is detected.

## Status

Architecture design: In Progress
