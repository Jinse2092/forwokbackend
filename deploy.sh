#!/bin/bash
cd /home/ec2-user/forwokbackend
git pull origin main
npm install --production
pm2 restart backend
