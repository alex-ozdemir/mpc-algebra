library(tidyverse)
d <- read_csv("./analysis/data/groth16.csv")
data <- d %>%
    transmute(constraints=constraints, ark_local=ark_local_time, mpc=mpc_time, local=local_time) %>%
    pivot_longer(!constraints, names_to = "infra", values_to = "time")
legend_label = "System"
ggplot(data=data, mapping = aes(y = time, x = constraints, color = infra, linetype=infra, shape=infra)) +
  geom_line() +
  geom_point(size=4) +
  scale_y_continuous(trans = "log10") +
  scale_x_continuous(trans = "log10") +
  labs(x = "Constraints",
       y = "Time (s)",
       color = legend_label,
       linetype = legend_label,
       shape = legend_label
       )
ggsave("./analysis/plots/groth16.png")
