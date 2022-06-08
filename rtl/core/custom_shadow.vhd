
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

library neorv32;
use neorv32.neorv32_package.all;

entity neorv32_shadow is
  port (
    clk_i  : in  std_ulogic; -- global clock line
    rstn_i        : in  std_ulogic; -- global reset, low-active, async
    rden_i : in  std_ulogic; -- read enable
    wren_i : in  std_ulogic; -- write enable
    data_store : in  std_ulogic_vector(31 downto 0); -- data in
    data_verif : in  std_ulogic_vector(31 downto 0); -- data in
    shadow_ok  : out std_ulogic -- transfer acknowledge
  );
end neorv32_shadow;

architecture neorv32_shadow_rtl of neorv32_shadow is
--stack
  signal mem_top_stack : mem8_t (0 to 0);
  signal mem_ra_stack : mem32_t(0 to 255);

--read data
  signal shadow_rd : std_ulogic;
begin

  --mem_top_stack(0) <= x"00";

  -- Memory Access --------------------------------------------------------------------------
  -- ----------------------------------------------------------------------------------------
  shadow_write: process(clk_i)
  begin
    if(rstn_i = '0') then
      mem_top_stack(0) <= x"00";
    elsif rising_edge(clk_i) then
      -- this RAM style should not require "no_rw_check" attributes as the read-after-write behavior
      -- is intended to be defined implicitly via the if-WRITE-else-READ construct
        if (wren_i = '1') then -- byte 0
          mem_ra_stack(to_integer(unsigned(mem_top_stack(0))) + 1) <= data_store(31 downto 00);
          mem_top_stack(0) <= std_ulogic_vector(to_unsigned(to_integer(unsigned(mem_top_stack(0))) + 1, 8));
        end if;
        if(shadow_rd = '1') then
          mem_top_stack(0) <= std_ulogic_vector(to_unsigned(to_integer(unsigned(mem_top_stack(0))) - 1, 8));
        end if;
    end if;
  end process shadow_write;

  shadow_read: process(rden_i, mem_ra_stack, data_verif, mem_top_stack)
  begin
    if(rden_i = '1' and mem_ra_stack(to_integer(unsigned(mem_top_stack(0)))) = data_verif(31 downto 0)) then
        shadow_ok <= '1';
        shadow_rd <= '1';
    else
        shadow_ok <= '0';
        shadow_rd <= '0';
    end if;
  end process shadow_read;

end neorv32_shadow_rtl;
