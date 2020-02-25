FROM kolide/fleet:2.5.0
RUN mkdir /etc/kolide
COPY conf/kolide.yml /etc/kolide/kolide.yml
CMD ["fleet", "serve", "--config", "/etc/kolide/kolide.yml"]